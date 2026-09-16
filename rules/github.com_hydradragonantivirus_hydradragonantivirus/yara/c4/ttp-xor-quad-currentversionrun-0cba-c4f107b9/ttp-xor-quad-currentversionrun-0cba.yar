rule TTP_XOR_QUAD_CurrentVersionRun_0cba {
  strings:
    $key_0cba = { 5f d5 [2] 7b db [2] 50 f7 [2] 7e d5 [2] 6a ce [2] 65 d4 [2] 7b c9 [2] 79 c8 [2] 62 ce [2] 7e c9 [2] 62 e6 }

  condition:
    any of them
}