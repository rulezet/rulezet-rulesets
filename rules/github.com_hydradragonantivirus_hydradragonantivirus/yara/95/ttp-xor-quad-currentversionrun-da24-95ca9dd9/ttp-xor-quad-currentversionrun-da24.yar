rule TTP_XOR_QUAD_CurrentVersionRun_da24 {
  strings:
    $key_da24 = { 89 4b [2] ad 45 [2] 86 69 [2] a8 4b [2] bc 50 [2] b3 4a [2] ad 57 [2] af 56 [2] b4 50 [2] a8 57 [2] b4 78 }

  condition:
    any of them
}