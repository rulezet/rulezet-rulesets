rule TTP_XOR_QUAD_CurrentVersionRun_485b {
  strings:
    $key_485b = { 1b 34 [2] 3f 3a [2] 14 16 [2] 3a 34 [2] 2e 2f [2] 21 35 [2] 3f 28 [2] 3d 29 [2] 26 2f [2] 3a 28 [2] 26 07 }

  condition:
    any of them
}