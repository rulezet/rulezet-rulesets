rule TTP_XOR_QUAD_CurrentVersionRun_da75 {
  strings:
    $key_da75 = { 89 1a [2] ad 14 [2] 86 38 [2] a8 1a [2] bc 01 [2] b3 1b [2] ad 06 [2] af 07 [2] b4 01 [2] a8 06 [2] b4 29 }

  condition:
    any of them
}