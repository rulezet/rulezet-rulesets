rule TTP_XOR_QUAD_CurrentVersionRun_64aa {
  strings:
    $key_64aa = { 37 c5 [2] 13 cb [2] 38 e7 [2] 16 c5 [2] 02 de [2] 0d c4 [2] 13 d9 [2] 11 d8 [2] 0a de [2] 16 d9 [2] 0a f6 }

  condition:
    any of them
}