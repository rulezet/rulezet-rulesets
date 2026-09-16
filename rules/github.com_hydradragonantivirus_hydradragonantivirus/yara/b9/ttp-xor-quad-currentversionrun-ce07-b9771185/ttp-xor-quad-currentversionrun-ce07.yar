rule TTP_XOR_QUAD_CurrentVersionRun_ce07 {
  strings:
    $key_ce07 = { 9d 68 [2] b9 66 [2] 92 4a [2] bc 68 [2] a8 73 [2] a7 69 [2] b9 74 [2] bb 75 [2] a0 73 [2] bc 74 [2] a0 5b }

  condition:
    any of them
}