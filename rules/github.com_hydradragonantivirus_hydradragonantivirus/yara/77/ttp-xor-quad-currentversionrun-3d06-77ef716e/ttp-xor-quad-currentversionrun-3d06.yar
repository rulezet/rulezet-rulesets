rule TTP_XOR_QUAD_CurrentVersionRun_3d06 {
  strings:
    $key_3d06 = { 6e 69 [2] 4a 67 [2] 61 4b [2] 4f 69 [2] 5b 72 [2] 54 68 [2] 4a 75 [2] 48 74 [2] 53 72 [2] 4f 75 [2] 53 5a }

  condition:
    any of them
}