rule TTP_XOR_QUAD_CurrentVersionRun_49ba {
  strings:
    $key_49ba = { 1a d5 [2] 3e db [2] 15 f7 [2] 3b d5 [2] 2f ce [2] 20 d4 [2] 3e c9 [2] 3c c8 [2] 27 ce [2] 3b c9 [2] 27 e6 }

  condition:
    any of them
}