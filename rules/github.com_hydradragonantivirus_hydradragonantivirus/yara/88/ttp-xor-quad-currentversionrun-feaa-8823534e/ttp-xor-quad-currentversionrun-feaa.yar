rule TTP_XOR_QUAD_CurrentVersionRun_feaa {
  strings:
    $key_feaa = { ad c5 [2] 89 cb [2] a2 e7 [2] 8c c5 [2] 98 de [2] 97 c4 [2] 89 d9 [2] 8b d8 [2] 90 de [2] 8c d9 [2] 90 f6 }

  condition:
    any of them
}