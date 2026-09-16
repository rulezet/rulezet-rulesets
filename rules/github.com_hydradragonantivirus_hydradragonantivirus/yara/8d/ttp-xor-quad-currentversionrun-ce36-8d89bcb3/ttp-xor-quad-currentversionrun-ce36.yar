rule TTP_XOR_QUAD_CurrentVersionRun_ce36 {
  strings:
    $key_ce36 = { 9d 59 [2] b9 57 [2] 92 7b [2] bc 59 [2] a8 42 [2] a7 58 [2] b9 45 [2] bb 44 [2] a0 42 [2] bc 45 [2] a0 6a }

  condition:
    any of them
}