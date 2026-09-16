rule TTP_XOR_QUAD_CurrentVersionRun_3bba {
  strings:
    $key_3bba = { 68 d5 [2] 4c db [2] 67 f7 [2] 49 d5 [2] 5d ce [2] 52 d4 [2] 4c c9 [2] 4e c8 [2] 55 ce [2] 49 c9 [2] 55 e6 }

  condition:
    any of them
}