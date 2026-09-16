rule TTP_XOR_QUAD_CurrentVersionRun_da72 {
  strings:
    $key_da72 = { 89 1d [2] ad 13 [2] 86 3f [2] a8 1d [2] bc 06 [2] b3 1c [2] ad 01 [2] af 00 [2] b4 06 [2] a8 01 [2] b4 2e }

  condition:
    any of them
}