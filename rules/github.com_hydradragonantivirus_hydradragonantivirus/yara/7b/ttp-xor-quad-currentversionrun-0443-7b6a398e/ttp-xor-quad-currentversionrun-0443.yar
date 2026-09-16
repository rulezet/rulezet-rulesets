rule TTP_XOR_QUAD_CurrentVersionRun_0443 {
  strings:
    $key_0443 = { 57 2c [2] 73 22 [2] 58 0e [2] 76 2c [2] 62 37 [2] 6d 2d [2] 73 30 [2] 71 31 [2] 6a 37 [2] 76 30 [2] 6a 1f }

  condition:
    any of them
}