rule TTP_XOR_QUAD_CurrentVersionRun_5aaa {
  strings:
    $key_5aaa = { 09 c5 [2] 2d cb [2] 06 e7 [2] 28 c5 [2] 3c de [2] 33 c4 [2] 2d d9 [2] 2f d8 [2] 34 de [2] 28 d9 [2] 34 f6 }

  condition:
    any of them
}