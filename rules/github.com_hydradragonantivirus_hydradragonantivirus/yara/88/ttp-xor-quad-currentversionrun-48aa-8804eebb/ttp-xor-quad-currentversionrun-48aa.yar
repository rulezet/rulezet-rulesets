rule TTP_XOR_QUAD_CurrentVersionRun_48aa {
  strings:
    $key_48aa = { 1b c5 [2] 3f cb [2] 14 e7 [2] 3a c5 [2] 2e de [2] 21 c4 [2] 3f d9 [2] 3d d8 [2] 26 de [2] 3a d9 [2] 26 f6 }

  condition:
    any of them
}