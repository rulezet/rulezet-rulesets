rule TTP_XOR_QUAD_CurrentVersionRun_ce54 {
  strings:
    $key_ce54 = { 9d 3b [2] b9 35 [2] 92 19 [2] bc 3b [2] a8 20 [2] a7 3a [2] b9 27 [2] bb 26 [2] a0 20 [2] bc 27 [2] a0 08 }

  condition:
    any of them
}