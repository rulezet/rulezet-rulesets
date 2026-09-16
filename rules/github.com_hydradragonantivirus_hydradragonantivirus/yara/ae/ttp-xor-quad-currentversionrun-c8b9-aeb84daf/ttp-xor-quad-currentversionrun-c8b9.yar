rule TTP_XOR_QUAD_CurrentVersionRun_c8b9 {
  strings:
    $key_c8b9 = { 9b d6 [2] bf d8 [2] 94 f4 [2] ba d6 [2] ae cd [2] a1 d7 [2] bf ca [2] bd cb [2] a6 cd [2] ba ca [2] a6 e5 }

  condition:
    any of them
}