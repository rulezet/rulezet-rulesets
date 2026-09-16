rule TTP_XOR_QUAD_CurrentVersionRun_2aaa {
  strings:
    $key_2aaa = { 79 c5 [2] 5d cb [2] 76 e7 [2] 58 c5 [2] 4c de [2] 43 c4 [2] 5d d9 [2] 5f d8 [2] 44 de [2] 58 d9 [2] 44 f6 }

  condition:
    any of them
}