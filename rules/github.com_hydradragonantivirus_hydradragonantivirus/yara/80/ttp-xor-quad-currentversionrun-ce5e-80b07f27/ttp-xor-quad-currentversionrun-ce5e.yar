rule TTP_XOR_QUAD_CurrentVersionRun_ce5e {
  strings:
    $key_ce5e = { 9d 31 [2] b9 3f [2] 92 13 [2] bc 31 [2] a8 2a [2] a7 30 [2] b9 2d [2] bb 2c [2] a0 2a [2] bc 2d [2] a0 02 }

  condition:
    any of them
}