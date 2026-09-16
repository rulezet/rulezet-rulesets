rule TTP_XOR_QUAD_CurrentVersionRun_caaa {
  strings:
    $key_caaa = { 99 c5 [2] bd cb [2] 96 e7 [2] b8 c5 [2] ac de [2] a3 c4 [2] bd d9 [2] bf d8 [2] a4 de [2] b8 d9 [2] a4 f6 }

  condition:
    any of them
}