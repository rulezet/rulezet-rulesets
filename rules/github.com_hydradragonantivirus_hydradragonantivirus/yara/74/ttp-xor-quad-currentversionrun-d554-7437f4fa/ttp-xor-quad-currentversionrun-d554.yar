rule TTP_XOR_QUAD_CurrentVersionRun_d554 {
  strings:
    $key_d554 = { 86 3b [2] a2 35 [2] 89 19 [2] a7 3b [2] b3 20 [2] bc 3a [2] a2 27 [2] a0 26 [2] bb 20 [2] a7 27 [2] bb 08 }

  condition:
    any of them
}