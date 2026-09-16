rule TTP_XOR_QUAD_CurrentVersionRun_c9f4 {
  strings:
    $key_c9f4 = { 9a 9b [2] be 95 [2] 95 b9 [2] bb 9b [2] af 80 [2] a0 9a [2] be 87 [2] bc 86 [2] a7 80 [2] bb 87 [2] a7 a8 }

  condition:
    any of them
}