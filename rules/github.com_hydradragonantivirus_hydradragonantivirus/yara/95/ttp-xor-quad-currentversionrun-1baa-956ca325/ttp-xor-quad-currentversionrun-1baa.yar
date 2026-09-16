rule TTP_XOR_QUAD_CurrentVersionRun_1baa {
  strings:
    $key_1baa = { 48 c5 [2] 6c cb [2] 47 e7 [2] 69 c5 [2] 7d de [2] 72 c4 [2] 6c d9 [2] 6e d8 [2] 75 de [2] 69 d9 [2] 75 f6 }

  condition:
    any of them
}