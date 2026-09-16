rule TTP_XOR_QUAD_CurrentVersionRun_ce74 {
  strings:
    $key_ce74 = { 9d 1b [2] b9 15 [2] 92 39 [2] bc 1b [2] a8 00 [2] a7 1a [2] b9 07 [2] bb 06 [2] a0 00 [2] bc 07 [2] a0 28 }

  condition:
    any of them
}