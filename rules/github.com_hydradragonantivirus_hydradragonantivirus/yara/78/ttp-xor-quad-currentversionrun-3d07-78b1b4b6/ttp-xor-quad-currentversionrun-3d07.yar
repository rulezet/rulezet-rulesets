rule TTP_XOR_QUAD_CurrentVersionRun_3d07 {
  strings:
    $key_3d07 = { 6e 68 [2] 4a 66 [2] 61 4a [2] 4f 68 [2] 5b 73 [2] 54 69 [2] 4a 74 [2] 48 75 [2] 53 73 [2] 4f 74 [2] 53 5b }

  condition:
    any of them
}