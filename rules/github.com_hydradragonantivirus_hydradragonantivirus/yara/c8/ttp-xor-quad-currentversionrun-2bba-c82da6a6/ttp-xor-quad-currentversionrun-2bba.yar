rule TTP_XOR_QUAD_CurrentVersionRun_2bba {
  strings:
    $key_2bba = { 78 d5 [2] 5c db [2] 77 f7 [2] 59 d5 [2] 4d ce [2] 42 d4 [2] 5c c9 [2] 5e c8 [2] 45 ce [2] 59 c9 [2] 45 e6 }

  condition:
    any of them
}