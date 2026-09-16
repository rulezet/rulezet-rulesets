rule TTP_XOR_QUAD_CurrentVersionRun_c8b8 {
  strings:
    $key_c8b8 = { 9b d7 [2] bf d9 [2] 94 f5 [2] ba d7 [2] ae cc [2] a1 d6 [2] bf cb [2] bd ca [2] a6 cc [2] ba cb [2] a6 e4 }

  condition:
    any of them
}