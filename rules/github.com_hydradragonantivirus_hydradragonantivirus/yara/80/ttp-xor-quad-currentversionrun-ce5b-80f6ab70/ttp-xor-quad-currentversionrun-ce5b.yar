rule TTP_XOR_QUAD_CurrentVersionRun_ce5b {
  strings:
    $key_ce5b = { 9d 34 [2] b9 3a [2] 92 16 [2] bc 34 [2] a8 2f [2] a7 35 [2] b9 28 [2] bb 29 [2] a0 2f [2] bc 28 [2] a0 07 }

  condition:
    any of them
}