rule TTP_XOR_QUAD_CurrentVersionRun_ce04 {
  strings:
    $key_ce04 = { 9d 6b [2] b9 65 [2] 92 49 [2] bc 6b [2] a8 70 [2] a7 6a [2] b9 77 [2] bb 76 [2] a0 70 [2] bc 77 [2] a0 58 }

  condition:
    any of them
}