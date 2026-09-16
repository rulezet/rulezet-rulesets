rule TTP_XOR_QUAD_CurrentVersionRun_da6f {
  strings:
    $key_da6f = { 89 00 [2] ad 0e [2] 86 22 [2] a8 00 [2] bc 1b [2] b3 01 [2] ad 1c [2] af 1d [2] b4 1b [2] a8 1c [2] b4 33 }

  condition:
    any of them
}