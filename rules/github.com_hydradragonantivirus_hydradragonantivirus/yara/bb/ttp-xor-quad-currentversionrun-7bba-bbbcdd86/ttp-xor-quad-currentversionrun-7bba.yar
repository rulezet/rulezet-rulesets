rule TTP_XOR_QUAD_CurrentVersionRun_7bba {
  strings:
    $key_7bba = { 28 d5 [2] 0c db [2] 27 f7 [2] 09 d5 [2] 1d ce [2] 12 d4 [2] 0c c9 [2] 0e c8 [2] 15 ce [2] 09 c9 [2] 15 e6 }

  condition:
    any of them
}