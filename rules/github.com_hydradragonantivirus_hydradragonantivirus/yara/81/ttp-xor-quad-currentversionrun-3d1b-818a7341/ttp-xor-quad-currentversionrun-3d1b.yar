rule TTP_XOR_QUAD_CurrentVersionRun_3d1b {
  strings:
    $key_3d1b = { 6e 74 [2] 4a 7a [2] 61 56 [2] 4f 74 [2] 5b 6f [2] 54 75 [2] 4a 68 [2] 48 69 [2] 53 6f [2] 4f 68 [2] 53 47 }

  condition:
    any of them
}