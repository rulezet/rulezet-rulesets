rule TTP_XOR_QUAD_CurrentVersionRun_5cba {
  strings:
    $key_5cba = { 0f d5 [2] 2b db [2] 00 f7 [2] 2e d5 [2] 3a ce [2] 35 d4 [2] 2b c9 [2] 29 c8 [2] 32 ce [2] 2e c9 [2] 32 e6 }

  condition:
    any of them
}