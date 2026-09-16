rule TTP_XOR_QUAD_CurrentVersionRun_5caa {
  strings:
    $key_5caa = { 0f c5 [2] 2b cb [2] 00 e7 [2] 2e c5 [2] 3a de [2] 35 c4 [2] 2b d9 [2] 29 d8 [2] 32 de [2] 2e d9 [2] 32 f6 }

  condition:
    any of them
}