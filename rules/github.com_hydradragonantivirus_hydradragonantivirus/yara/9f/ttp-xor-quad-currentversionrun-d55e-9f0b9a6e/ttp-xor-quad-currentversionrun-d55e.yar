rule TTP_XOR_QUAD_CurrentVersionRun_d55e {
  strings:
    $key_d55e = { 86 31 [2] a2 3f [2] 89 13 [2] a7 31 [2] b3 2a [2] bc 30 [2] a2 2d [2] a0 2c [2] bb 2a [2] a7 2d [2] bb 02 }

  condition:
    any of them
}