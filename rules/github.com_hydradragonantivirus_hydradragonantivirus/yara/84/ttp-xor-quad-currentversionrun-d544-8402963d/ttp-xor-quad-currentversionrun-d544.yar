rule TTP_XOR_QUAD_CurrentVersionRun_d544 {
  strings:
    $key_d544 = { 86 2b [2] a2 25 [2] 89 09 [2] a7 2b [2] b3 30 [2] bc 2a [2] a2 37 [2] a0 36 [2] bb 30 [2] a7 37 [2] bb 18 }

  condition:
    any of them
}