rule TTP_XOR_QUAD_CurrentVersionRun_da40 {
  strings:
    $key_da40 = { 89 2f [2] ad 21 [2] 86 0d [2] a8 2f [2] bc 34 [2] b3 2e [2] ad 33 [2] af 32 [2] b4 34 [2] a8 33 [2] b4 1c }

  condition:
    any of them
}