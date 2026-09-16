rule TTP_XOR_QUAD_CurrentVersionRun_ce47 {
  strings:
    $key_ce47 = { 9d 28 [2] b9 26 [2] 92 0a [2] bc 28 [2] a8 33 [2] a7 29 [2] b9 34 [2] bb 35 [2] a0 33 [2] bc 34 [2] a0 1b }

  condition:
    any of them
}