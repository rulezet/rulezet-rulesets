rule TTP_XOR_QUAD_CurrentVersionRun_ce38 {
  strings:
    $key_ce38 = { 9d 57 [2] b9 59 [2] 92 75 [2] bc 57 [2] a8 4c [2] a7 56 [2] b9 4b [2] bb 4a [2] a0 4c [2] bc 4b [2] a0 64 }

  condition:
    any of them
}