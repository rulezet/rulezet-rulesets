rule TTP_XOR_QUAD_CurrentVersionRun_5f43 {
  strings:
    $key_5f43 = { 0c 2c [2] 28 22 [2] 03 0e [2] 2d 2c [2] 39 37 [2] 36 2d [2] 28 30 [2] 2a 31 [2] 31 37 [2] 2d 30 [2] 31 1f }

  condition:
    any of them
}