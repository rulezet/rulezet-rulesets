rule TTP_XOR_QUAD_CurrentVersionRun_7343 {
  strings:
    $key_7343 = { 20 2c [2] 04 22 [2] 2f 0e [2] 01 2c [2] 15 37 [2] 1a 2d [2] 04 30 [2] 06 31 [2] 1d 37 [2] 01 30 [2] 1d 1f }

  condition:
    any of them
}