rule TTP_XOR_QUAD_CurrentVersionRun_7cba {
  strings:
    $key_7cba = { 2f d5 [2] 0b db [2] 20 f7 [2] 0e d5 [2] 1a ce [2] 15 d4 [2] 0b c9 [2] 09 c8 [2] 12 ce [2] 0e c9 [2] 12 e6 }

  condition:
    any of them
}