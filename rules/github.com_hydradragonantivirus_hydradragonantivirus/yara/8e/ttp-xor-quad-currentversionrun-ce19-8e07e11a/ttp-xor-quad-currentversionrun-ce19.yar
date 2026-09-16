rule TTP_XOR_QUAD_CurrentVersionRun_ce19 {
  strings:
    $key_ce19 = { 9d 76 [2] b9 78 [2] 92 54 [2] bc 76 [2] a8 6d [2] a7 77 [2] b9 6a [2] bb 6b [2] a0 6d [2] bc 6a [2] a0 45 }

  condition:
    any of them
}