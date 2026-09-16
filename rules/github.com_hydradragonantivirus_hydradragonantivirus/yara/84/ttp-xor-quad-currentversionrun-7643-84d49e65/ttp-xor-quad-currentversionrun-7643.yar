rule TTP_XOR_QUAD_CurrentVersionRun_7643 {
  strings:
    $key_7643 = { 25 2c [2] 01 22 [2] 2a 0e [2] 04 2c [2] 10 37 [2] 1f 2d [2] 01 30 [2] 03 31 [2] 18 37 [2] 04 30 [2] 18 1f }

  condition:
    any of them
}