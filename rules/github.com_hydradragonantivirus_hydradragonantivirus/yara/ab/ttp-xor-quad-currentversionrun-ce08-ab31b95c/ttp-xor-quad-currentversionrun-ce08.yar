rule TTP_XOR_QUAD_CurrentVersionRun_ce08 {
  strings:
    $key_ce08 = { 9d 67 [2] b9 69 [2] 92 45 [2] bc 67 [2] a8 7c [2] a7 66 [2] b9 7b [2] bb 7a [2] a0 7c [2] bc 7b [2] a0 54 }

  condition:
    any of them
}