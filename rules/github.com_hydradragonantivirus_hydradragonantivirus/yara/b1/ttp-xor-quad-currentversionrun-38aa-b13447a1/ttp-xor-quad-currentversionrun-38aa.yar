rule TTP_XOR_QUAD_CurrentVersionRun_38aa {
  strings:
    $key_38aa = { 6b c5 [2] 4f cb [2] 64 e7 [2] 4a c5 [2] 5e de [2] 51 c4 [2] 4f d9 [2] 4d d8 [2] 56 de [2] 4a d9 [2] 56 f6 }

  condition:
    any of them
}