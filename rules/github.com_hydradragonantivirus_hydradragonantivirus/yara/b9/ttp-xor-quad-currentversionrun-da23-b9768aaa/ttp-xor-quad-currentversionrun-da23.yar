rule TTP_XOR_QUAD_CurrentVersionRun_da23 {
  strings:
    $key_da23 = { 89 4c [2] ad 42 [2] 86 6e [2] a8 4c [2] bc 57 [2] b3 4d [2] ad 50 [2] af 51 [2] b4 57 [2] a8 50 [2] b4 7f }

  condition:
    any of them
}