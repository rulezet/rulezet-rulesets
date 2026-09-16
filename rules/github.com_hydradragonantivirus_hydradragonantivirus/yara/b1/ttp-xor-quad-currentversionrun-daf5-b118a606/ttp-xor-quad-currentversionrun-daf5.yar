rule TTP_XOR_QUAD_CurrentVersionRun_daf5 {
  strings:
    $key_daf5 = { 89 9a [2] ad 94 [2] 86 b8 [2] a8 9a [2] bc 81 [2] b3 9b [2] ad 86 [2] af 87 [2] b4 81 [2] a8 86 [2] b4 a9 }

  condition:
    any of them
}