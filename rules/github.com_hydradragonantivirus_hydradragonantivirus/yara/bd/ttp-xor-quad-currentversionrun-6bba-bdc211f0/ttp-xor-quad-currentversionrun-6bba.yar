rule TTP_XOR_QUAD_CurrentVersionRun_6bba {
  strings:
    $key_6bba = { 38 d5 [2] 1c db [2] 37 f7 [2] 19 d5 [2] 0d ce [2] 02 d4 [2] 1c c9 [2] 1e c8 [2] 05 ce [2] 19 c9 [2] 05 e6 }

  condition:
    any of them
}