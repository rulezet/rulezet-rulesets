rule TTP_XOR_QUAD_CurrentVersionRun_ce68 {
  strings:
    $key_ce68 = { 9d 07 [2] b9 09 [2] 92 25 [2] bc 07 [2] a8 1c [2] a7 06 [2] b9 1b [2] bb 1a [2] a0 1c [2] bc 1b [2] a0 34 }

  condition:
    any of them
}