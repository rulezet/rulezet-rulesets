rule TTP_XOR_QUAD_CurrentVersionRun_da5f {
  strings:
    $key_da5f = { 89 30 [2] ad 3e [2] 86 12 [2] a8 30 [2] bc 2b [2] b3 31 [2] ad 2c [2] af 2d [2] b4 2b [2] a8 2c [2] b4 03 }

  condition:
    any of them
}