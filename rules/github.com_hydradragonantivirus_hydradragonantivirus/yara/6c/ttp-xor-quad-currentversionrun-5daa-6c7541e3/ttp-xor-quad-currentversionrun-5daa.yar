rule TTP_XOR_QUAD_CurrentVersionRun_5daa {
  strings:
    $key_5daa = { 0e c5 [2] 2a cb [2] 01 e7 [2] 2f c5 [2] 3b de [2] 34 c4 [2] 2a d9 [2] 28 d8 [2] 33 de [2] 2f d9 [2] 33 f6 }

  condition:
    any of them
}