rule TTP_XOR_QUAD_CurrentVersionRun_4843 {
  strings:
    $key_4843 = { 1b 2c [2] 3f 22 [2] 14 0e [2] 3a 2c [2] 2e 37 [2] 21 2d [2] 3f 30 [2] 3d 31 [2] 26 37 [2] 3a 30 [2] 26 1f }

  condition:
    any of them
}