rule TTP_XOR_QUAD_CurrentVersionRun_0eaa {
  strings:
    $key_0eaa = { 5d c5 [2] 79 cb [2] 52 e7 [2] 7c c5 [2] 68 de [2] 67 c4 [2] 79 d9 [2] 7b d8 [2] 60 de [2] 7c d9 [2] 60 f6 }

  condition:
    any of them
}