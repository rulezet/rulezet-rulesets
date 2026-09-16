rule TTP_XOR_QUAD_CurrentVersionRun_78aa {
  strings:
    $key_78aa = { 2b c5 [2] 0f cb [2] 24 e7 [2] 0a c5 [2] 1e de [2] 11 c4 [2] 0f d9 [2] 0d d8 [2] 16 de [2] 0a d9 [2] 16 f6 }

  condition:
    any of them
}