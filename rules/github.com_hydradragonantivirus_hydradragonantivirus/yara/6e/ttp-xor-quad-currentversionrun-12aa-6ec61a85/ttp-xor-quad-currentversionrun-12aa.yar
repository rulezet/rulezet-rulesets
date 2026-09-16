rule TTP_XOR_QUAD_CurrentVersionRun_12aa {
  strings:
    $key_12aa = { 41 c5 [2] 65 cb [2] 4e e7 [2] 60 c5 [2] 74 de [2] 7b c4 [2] 65 d9 [2] 67 d8 [2] 7c de [2] 60 d9 [2] 7c f6 }

  condition:
    any of them
}