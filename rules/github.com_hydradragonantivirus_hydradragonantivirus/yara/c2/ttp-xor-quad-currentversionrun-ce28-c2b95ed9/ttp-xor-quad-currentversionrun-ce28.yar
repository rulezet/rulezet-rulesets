rule TTP_XOR_QUAD_CurrentVersionRun_ce28 {
  strings:
    $key_ce28 = { 9d 47 [2] b9 49 [2] 92 65 [2] bc 47 [2] a8 5c [2] a7 46 [2] b9 5b [2] bb 5a [2] a0 5c [2] bc 5b [2] a0 74 }

  condition:
    any of them
}