rule TTP_XOR_QUAD_CurrentVersionRun_47aa {
  strings:
    $key_47aa = { 14 c5 [2] 30 cb [2] 1b e7 [2] 35 c5 [2] 21 de [2] 2e c4 [2] 30 d9 [2] 32 d8 [2] 29 de [2] 35 d9 [2] 29 f6 }

  condition:
    any of them
}