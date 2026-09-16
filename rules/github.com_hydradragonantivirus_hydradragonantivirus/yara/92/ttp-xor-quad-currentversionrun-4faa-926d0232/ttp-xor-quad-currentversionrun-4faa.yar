rule TTP_XOR_QUAD_CurrentVersionRun_4faa {
  strings:
    $key_4faa = { 1c c5 [2] 38 cb [2] 13 e7 [2] 3d c5 [2] 29 de [2] 26 c4 [2] 38 d9 [2] 3a d8 [2] 21 de [2] 3d d9 [2] 21 f6 }

  condition:
    any of them
}