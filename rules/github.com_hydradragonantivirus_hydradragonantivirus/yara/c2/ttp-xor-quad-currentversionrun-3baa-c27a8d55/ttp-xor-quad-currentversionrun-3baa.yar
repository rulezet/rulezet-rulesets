rule TTP_XOR_QUAD_CurrentVersionRun_3baa {
  strings:
    $key_3baa = { 68 c5 [2] 4c cb [2] 67 e7 [2] 49 c5 [2] 5d de [2] 52 c4 [2] 4c d9 [2] 4e d8 [2] 55 de [2] 49 d9 [2] 55 f6 }

  condition:
    any of them
}