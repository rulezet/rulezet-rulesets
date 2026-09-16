rule TTP_XOR_QUAD_CurrentVersionRun_d2f4 {
  strings:
    $key_d2f4 = { 81 9b [2] a5 95 [2] 8e b9 [2] a0 9b [2] b4 80 [2] bb 9a [2] a5 87 [2] a7 86 [2] bc 80 [2] a0 87 [2] bc a8 }

  condition:
    any of them
}