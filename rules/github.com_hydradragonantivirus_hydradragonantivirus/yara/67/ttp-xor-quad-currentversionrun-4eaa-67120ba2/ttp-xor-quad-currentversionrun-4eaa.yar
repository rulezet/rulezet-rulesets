rule TTP_XOR_QUAD_CurrentVersionRun_4eaa {
  strings:
    $key_4eaa = { 1d c5 [2] 39 cb [2] 12 e7 [2] 3c c5 [2] 28 de [2] 27 c4 [2] 39 d9 [2] 3b d8 [2] 20 de [2] 3c d9 [2] 20 f6 }

  condition:
    any of them
}