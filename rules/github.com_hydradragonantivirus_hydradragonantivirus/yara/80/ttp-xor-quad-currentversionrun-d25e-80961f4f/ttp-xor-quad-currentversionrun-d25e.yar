rule TTP_XOR_QUAD_CurrentVersionRun_d25e {
  strings:
    $key_d25e = { 81 31 [2] a5 3f [2] 8e 13 [2] a0 31 [2] b4 2a [2] bb 30 [2] a5 2d [2] a7 2c [2] bc 2a [2] a0 2d [2] bc 02 }

  condition:
    any of them
}