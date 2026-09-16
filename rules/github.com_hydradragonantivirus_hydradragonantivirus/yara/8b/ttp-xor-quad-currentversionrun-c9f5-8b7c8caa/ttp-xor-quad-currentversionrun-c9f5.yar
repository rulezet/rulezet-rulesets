rule TTP_XOR_QUAD_CurrentVersionRun_c9f5 {
  strings:
    $key_c9f5 = { 9a 9a [2] be 94 [2] 95 b8 [2] bb 9a [2] af 81 [2] a0 9b [2] be 86 [2] bc 87 [2] a7 81 [2] bb 86 [2] a7 a9 }

  condition:
    any of them
}