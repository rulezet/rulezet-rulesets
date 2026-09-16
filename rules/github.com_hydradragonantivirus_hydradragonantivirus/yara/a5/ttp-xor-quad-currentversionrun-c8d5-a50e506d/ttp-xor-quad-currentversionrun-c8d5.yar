rule TTP_XOR_QUAD_CurrentVersionRun_c8d5 {
  strings:
    $key_c8d5 = { 9b ba [2] bf b4 [2] 94 98 [2] ba ba [2] ae a1 [2] a1 bb [2] bf a6 [2] bd a7 [2] a6 a1 [2] ba a6 [2] a6 89 }

  condition:
    any of them
}