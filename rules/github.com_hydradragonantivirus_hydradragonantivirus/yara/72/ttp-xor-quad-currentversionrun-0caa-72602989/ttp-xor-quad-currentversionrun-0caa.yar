rule TTP_XOR_QUAD_CurrentVersionRun_0caa {
  strings:
    $key_0caa = { 5f c5 [2] 7b cb [2] 50 e7 [2] 7e c5 [2] 6a de [2] 65 c4 [2] 7b d9 [2] 79 d8 [2] 62 de [2] 7e d9 [2] 62 f6 }

  condition:
    any of them
}