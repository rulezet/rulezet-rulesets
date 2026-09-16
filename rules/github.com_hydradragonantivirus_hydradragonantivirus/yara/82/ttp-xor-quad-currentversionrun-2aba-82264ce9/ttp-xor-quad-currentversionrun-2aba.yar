rule TTP_XOR_QUAD_CurrentVersionRun_2aba {
  strings:
    $key_2aba = { 79 d5 [2] 5d db [2] 76 f7 [2] 58 d5 [2] 4c ce [2] 43 d4 [2] 5d c9 [2] 5f c8 [2] 44 ce [2] 58 c9 [2] 44 e6 }

  condition:
    any of them
}