rule TTP_XOR_QUAD_CurrentVersionRun_4baa {
  strings:
    $key_4baa = { 18 c5 [2] 3c cb [2] 17 e7 [2] 39 c5 [2] 2d de [2] 22 c4 [2] 3c d9 [2] 3e d8 [2] 25 de [2] 39 d9 [2] 25 f6 }

  condition:
    any of them
}