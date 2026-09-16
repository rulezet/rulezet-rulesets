rule TTP_XOR_QUAD_CurrentVersionRun_29ba {
  strings:
    $key_29ba = { 7a d5 [2] 5e db [2] 75 f7 [2] 5b d5 [2] 4f ce [2] 40 d4 [2] 5e c9 [2] 5c c8 [2] 47 ce [2] 5b c9 [2] 47 e6 }

  condition:
    any of them
}