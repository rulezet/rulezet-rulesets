rule TTP_XOR_QUAD_CurrentVersionRun_c8d4 {
  strings:
    $key_c8d4 = { 9b bb [2] bf b5 [2] 94 99 [2] ba bb [2] ae a0 [2] a1 ba [2] bf a7 [2] bd a6 [2] a6 a0 [2] ba a7 [2] a6 88 }

  condition:
    any of them
}