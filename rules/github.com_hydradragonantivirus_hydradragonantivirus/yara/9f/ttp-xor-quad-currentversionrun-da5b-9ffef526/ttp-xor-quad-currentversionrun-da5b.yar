rule TTP_XOR_QUAD_CurrentVersionRun_da5b {
  strings:
    $key_da5b = { 89 34 [2] ad 3a [2] 86 16 [2] a8 34 [2] bc 2f [2] b3 35 [2] ad 28 [2] af 29 [2] b4 2f [2] a8 28 [2] b4 07 }

  condition:
    any of them
}