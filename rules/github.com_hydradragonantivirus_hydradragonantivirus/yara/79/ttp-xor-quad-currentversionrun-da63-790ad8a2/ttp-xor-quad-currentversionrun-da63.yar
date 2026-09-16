rule TTP_XOR_QUAD_CurrentVersionRun_da63 {
  strings:
    $key_da63 = { 89 0c [2] ad 02 [2] 86 2e [2] a8 0c [2] bc 17 [2] b3 0d [2] ad 10 [2] af 11 [2] b4 17 [2] a8 10 [2] b4 3f }

  condition:
    any of them
}