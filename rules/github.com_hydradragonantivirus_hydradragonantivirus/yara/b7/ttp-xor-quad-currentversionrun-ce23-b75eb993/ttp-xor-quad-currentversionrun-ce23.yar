rule TTP_XOR_QUAD_CurrentVersionRun_ce23 {
  strings:
    $key_ce23 = { 9d 4c [2] b9 42 [2] 92 6e [2] bc 4c [2] a8 57 [2] a7 4d [2] b9 50 [2] bb 51 [2] a0 57 [2] bc 50 [2] a0 7f }

  condition:
    any of them
}