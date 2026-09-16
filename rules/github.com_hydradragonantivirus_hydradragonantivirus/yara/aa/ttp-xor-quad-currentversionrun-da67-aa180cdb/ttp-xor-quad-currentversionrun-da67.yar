rule TTP_XOR_QUAD_CurrentVersionRun_da67 {
  strings:
    $key_da67 = { 89 08 [2] ad 06 [2] 86 2a [2] a8 08 [2] bc 13 [2] b3 09 [2] ad 14 [2] af 15 [2] b4 13 [2] a8 14 [2] b4 3b }

  condition:
    any of them
}