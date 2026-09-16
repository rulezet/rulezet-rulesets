rule TTP_XOR_QUAD_CurrentVersionRun_7aaa {
  strings:
    $key_7aaa = { 29 c5 [2] 0d cb [2] 26 e7 [2] 08 c5 [2] 1c de [2] 13 c4 [2] 0d d9 [2] 0f d8 [2] 14 de [2] 08 d9 [2] 14 f6 }

  condition:
    any of them
}