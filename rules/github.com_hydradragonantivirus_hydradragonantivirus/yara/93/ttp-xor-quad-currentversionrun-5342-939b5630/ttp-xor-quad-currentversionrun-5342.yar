rule TTP_XOR_QUAD_CurrentVersionRun_5342 {
  strings:
    $key_5342 = { 00 2d [2] 24 23 [2] 0f 0f [2] 21 2d [2] 35 36 [2] 3a 2c [2] 24 31 [2] 26 30 [2] 3d 36 [2] 21 31 [2] 3d 1e }

  condition:
    any of them
}