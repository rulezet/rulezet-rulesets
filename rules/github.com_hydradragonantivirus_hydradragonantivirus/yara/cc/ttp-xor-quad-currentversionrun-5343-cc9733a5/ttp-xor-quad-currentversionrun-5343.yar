rule TTP_XOR_QUAD_CurrentVersionRun_5343 {
  strings:
    $key_5343 = { 00 2c [2] 24 22 [2] 0f 0e [2] 21 2c [2] 35 37 [2] 3a 2d [2] 24 30 [2] 26 31 [2] 3d 37 [2] 21 30 [2] 3d 1f }

  condition:
    any of them
}