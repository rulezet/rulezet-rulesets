rule TTP_XOR_QUAD_CurrentVersionRun_1bba {
  strings:
    $key_1bba = { 48 d5 [2] 6c db [2] 47 f7 [2] 69 d5 [2] 7d ce [2] 72 d4 [2] 6c c9 [2] 6e c8 [2] 75 ce [2] 69 c9 [2] 75 e6 }

  condition:
    any of them
}