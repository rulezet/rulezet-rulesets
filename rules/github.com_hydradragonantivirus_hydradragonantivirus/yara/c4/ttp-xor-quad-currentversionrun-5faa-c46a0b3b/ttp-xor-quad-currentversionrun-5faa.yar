rule TTP_XOR_QUAD_CurrentVersionRun_5faa {
  strings:
    $key_5faa = { 0c c5 [2] 28 cb [2] 03 e7 [2] 2d c5 [2] 39 de [2] 36 c4 [2] 28 d9 [2] 2a d8 [2] 31 de [2] 2d d9 [2] 31 f6 }

  condition:
    any of them
}