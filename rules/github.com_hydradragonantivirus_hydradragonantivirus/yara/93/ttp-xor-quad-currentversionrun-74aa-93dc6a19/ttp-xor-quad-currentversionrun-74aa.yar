rule TTP_XOR_QUAD_CurrentVersionRun_74aa {
  strings:
    $key_74aa = { 27 c5 [2] 03 cb [2] 28 e7 [2] 06 c5 [2] 12 de [2] 1d c4 [2] 03 d9 [2] 01 d8 [2] 1a de [2] 06 d9 [2] 1a f6 }

  condition:
    any of them
}