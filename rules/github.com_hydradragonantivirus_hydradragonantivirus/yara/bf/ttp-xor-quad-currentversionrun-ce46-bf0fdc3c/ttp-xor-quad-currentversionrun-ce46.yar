rule TTP_XOR_QUAD_CurrentVersionRun_ce46 {
  strings:
    $key_ce46 = { 9d 29 [2] b9 27 [2] 92 0b [2] bc 29 [2] a8 32 [2] a7 28 [2] b9 35 [2] bb 34 [2] a0 32 [2] bc 35 [2] a0 1a }

  condition:
    any of them
}