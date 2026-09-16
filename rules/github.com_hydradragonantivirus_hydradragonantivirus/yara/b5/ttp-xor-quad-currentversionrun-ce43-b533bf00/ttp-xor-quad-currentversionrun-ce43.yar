rule TTP_XOR_QUAD_CurrentVersionRun_ce43 {
  strings:
    $key_ce43 = { 9d 2c [2] b9 22 [2] 92 0e [2] bc 2c [2] a8 37 [2] a7 2d [2] b9 30 [2] bb 31 [2] a0 37 [2] bc 30 [2] a0 1f }

  condition:
    any of them
}