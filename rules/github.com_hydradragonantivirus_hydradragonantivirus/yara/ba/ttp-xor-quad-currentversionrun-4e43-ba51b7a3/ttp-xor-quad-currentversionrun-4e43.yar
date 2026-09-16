rule TTP_XOR_QUAD_CurrentVersionRun_4e43 {
  strings:
    $key_4e43 = { 1d 2c [2] 39 22 [2] 12 0e [2] 3c 2c [2] 28 37 [2] 27 2d [2] 39 30 [2] 3b 31 [2] 20 37 [2] 3c 30 [2] 20 1f }

  condition:
    any of them
}