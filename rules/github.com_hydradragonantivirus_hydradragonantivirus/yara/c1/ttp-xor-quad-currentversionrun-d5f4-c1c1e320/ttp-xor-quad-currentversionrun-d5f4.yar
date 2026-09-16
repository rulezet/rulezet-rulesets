rule TTP_XOR_QUAD_CurrentVersionRun_d5f4 {
  strings:
    $key_d5f4 = { 86 9b [2] a2 95 [2] 89 b9 [2] a7 9b [2] b3 80 [2] bc 9a [2] a2 87 [2] a0 86 [2] bb 80 [2] a7 87 [2] bb a8 }

  condition:
    any of them
}