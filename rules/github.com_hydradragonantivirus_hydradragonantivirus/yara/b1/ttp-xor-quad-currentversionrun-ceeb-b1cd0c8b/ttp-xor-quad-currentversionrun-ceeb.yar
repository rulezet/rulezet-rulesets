rule TTP_XOR_QUAD_CurrentVersionRun_ceeb {
  strings:
    $key_ceeb = { 9d 84 [2] b9 8a [2] 92 a6 [2] bc 84 [2] a8 9f [2] a7 85 [2] b9 98 [2] bb 99 [2] a0 9f [2] bc 98 [2] a0 b7 }

  condition:
    any of them
}