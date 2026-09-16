rule TTP_XOR_QUAD_CurrentVersionRun_da17 {
  strings:
    $key_da17 = { 89 78 [2] ad 76 [2] 86 5a [2] a8 78 [2] bc 63 [2] b3 79 [2] ad 64 [2] af 65 [2] b4 63 [2] a8 64 [2] b4 4b }

  condition:
    any of them
}