rule TTP_XOR_QUAD_CurrentVersionRun_58aa {
  strings:
    $key_58aa = { 0b c5 [2] 2f cb [2] 04 e7 [2] 2a c5 [2] 3e de [2] 31 c4 [2] 2f d9 [2] 2d d8 [2] 36 de [2] 2a d9 [2] 36 f6 }

  condition:
    any of them
}