rule TTP_XOR_QUAD_CurrentVersionRun_d548 {
  strings:
    $key_d548 = { 86 27 [2] a2 29 [2] 89 05 [2] a7 27 [2] b3 3c [2] bc 26 [2] a2 3b [2] a0 3a [2] bb 3c [2] a7 3b [2] bb 14 }

  condition:
    any of them
}