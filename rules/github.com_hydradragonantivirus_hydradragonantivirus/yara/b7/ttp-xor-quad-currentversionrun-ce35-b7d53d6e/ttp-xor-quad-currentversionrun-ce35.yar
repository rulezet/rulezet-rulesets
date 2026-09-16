rule TTP_XOR_QUAD_CurrentVersionRun_ce35 {
  strings:
    $key_ce35 = { 9d 5a [2] b9 54 [2] 92 78 [2] bc 5a [2] a8 41 [2] a7 5b [2] b9 46 [2] bb 47 [2] a0 41 [2] bc 46 [2] a0 69 }

  condition:
    any of them
}