rule TTP_XOR_QUAD_CurrentVersionRun_fbba {
  strings:
    $key_fbba = { a8 d5 [2] 8c db [2] a7 f7 [2] 89 d5 [2] 9d ce [2] 92 d4 [2] 8c c9 [2] 8e c8 [2] 95 ce [2] 89 c9 [2] 95 e6 }

  condition:
    any of them
}