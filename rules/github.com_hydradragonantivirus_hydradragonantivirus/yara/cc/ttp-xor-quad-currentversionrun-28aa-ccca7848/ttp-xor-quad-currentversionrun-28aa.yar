rule TTP_XOR_QUAD_CurrentVersionRun_28aa {
  strings:
    $key_28aa = { 7b c5 [2] 5f cb [2] 74 e7 [2] 5a c5 [2] 4e de [2] 41 c4 [2] 5f d9 [2] 5d d8 [2] 46 de [2] 5a d9 [2] 46 f6 }

  condition:
    any of them
}