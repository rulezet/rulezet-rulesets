rule TTP_XOR_QUAD_CurrentVersionRun_da43 {
  strings:
    $key_da43 = { 89 2c [2] ad 22 [2] 86 0e [2] a8 2c [2] bc 37 [2] b3 2d [2] ad 30 [2] af 31 [2] b4 37 [2] a8 30 [2] b4 1f }

  condition:
    any of them
}