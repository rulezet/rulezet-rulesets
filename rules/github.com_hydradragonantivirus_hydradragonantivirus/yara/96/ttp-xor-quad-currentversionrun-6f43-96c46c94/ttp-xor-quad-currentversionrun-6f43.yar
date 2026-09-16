rule TTP_XOR_QUAD_CurrentVersionRun_6f43 {
  strings:
    $key_6f43 = { 3c 2c [2] 18 22 [2] 33 0e [2] 1d 2c [2] 09 37 [2] 06 2d [2] 18 30 [2] 1a 31 [2] 01 37 [2] 1d 30 [2] 01 1f }

  condition:
    any of them
}