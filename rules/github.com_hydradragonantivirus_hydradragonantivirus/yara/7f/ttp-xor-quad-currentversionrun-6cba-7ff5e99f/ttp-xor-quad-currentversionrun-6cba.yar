rule TTP_XOR_QUAD_CurrentVersionRun_6cba {
  strings:
    $key_6cba = { 3f d5 [2] 1b db [2] 30 f7 [2] 1e d5 [2] 0a ce [2] 05 d4 [2] 1b c9 [2] 19 c8 [2] 02 ce [2] 1e c9 [2] 02 e6 }

  condition:
    any of them
}