rule TTP_XOR_QUAD_CurrentVersionRun_c8d6 {
  strings:
    $key_c8d6 = { 9b b9 [2] bf b7 [2] 94 9b [2] ba b9 [2] ae a2 [2] a1 b8 [2] bf a5 [2] bd a4 [2] a6 a2 [2] ba a5 [2] a6 8a }

  condition:
    any of them
}