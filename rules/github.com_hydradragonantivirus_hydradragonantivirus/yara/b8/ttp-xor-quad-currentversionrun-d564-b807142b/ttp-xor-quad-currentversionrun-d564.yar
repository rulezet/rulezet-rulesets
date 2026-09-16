rule TTP_XOR_QUAD_CurrentVersionRun_d564 {
  strings:
    $key_d564 = { 86 0b [2] a2 05 [2] 89 29 [2] a7 0b [2] b3 10 [2] bc 0a [2] a2 17 [2] a0 16 [2] bb 10 [2] a7 17 [2] bb 38 }

  condition:
    any of them
}