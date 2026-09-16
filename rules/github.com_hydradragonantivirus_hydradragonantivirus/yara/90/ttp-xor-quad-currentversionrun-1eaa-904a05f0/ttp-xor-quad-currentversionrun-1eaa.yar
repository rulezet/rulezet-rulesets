rule TTP_XOR_QUAD_CurrentVersionRun_1eaa {
  strings:
    $key_1eaa = { 4d c5 [2] 69 cb [2] 42 e7 [2] 6c c5 [2] 78 de [2] 77 c4 [2] 69 d9 [2] 6b d8 [2] 70 de [2] 6c d9 [2] 70 f6 }

  condition:
    any of them
}