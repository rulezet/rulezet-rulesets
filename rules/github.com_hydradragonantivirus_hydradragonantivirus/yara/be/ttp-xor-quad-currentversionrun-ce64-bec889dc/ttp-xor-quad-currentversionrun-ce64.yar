rule TTP_XOR_QUAD_CurrentVersionRun_ce64 {
  strings:
    $key_ce64 = { 9d 0b [2] b9 05 [2] 92 29 [2] bc 0b [2] a8 10 [2] a7 0a [2] b9 17 [2] bb 16 [2] a0 10 [2] bc 17 [2] a0 38 }

  condition:
    any of them
}