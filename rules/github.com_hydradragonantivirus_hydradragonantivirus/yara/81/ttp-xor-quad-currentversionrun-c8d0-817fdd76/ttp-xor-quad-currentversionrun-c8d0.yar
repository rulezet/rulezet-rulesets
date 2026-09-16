rule TTP_XOR_QUAD_CurrentVersionRun_c8d0 {
  strings:
    $key_c8d0 = { 9b bf [2] bf b1 [2] 94 9d [2] ba bf [2] ae a4 [2] a1 be [2] bf a3 [2] bd a2 [2] a6 a4 [2] ba a3 [2] a6 8c }

  condition:
    any of them
}