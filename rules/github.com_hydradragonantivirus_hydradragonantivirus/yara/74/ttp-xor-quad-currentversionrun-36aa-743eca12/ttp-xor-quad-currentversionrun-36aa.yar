rule TTP_XOR_QUAD_CurrentVersionRun_36aa {
  strings:
    $key_36aa = { 65 c5 [2] 41 cb [2] 6a e7 [2] 44 c5 [2] 50 de [2] 5f c4 [2] 41 d9 [2] 43 d8 [2] 58 de [2] 44 d9 [2] 58 f6 }

  condition:
    any of them
}