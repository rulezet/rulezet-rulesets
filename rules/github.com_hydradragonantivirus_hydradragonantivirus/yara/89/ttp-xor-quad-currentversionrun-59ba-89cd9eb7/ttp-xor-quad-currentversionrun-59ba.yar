rule TTP_XOR_QUAD_CurrentVersionRun_59ba {
  strings:
    $key_59ba = { 0a d5 [2] 2e db [2] 05 f7 [2] 2b d5 [2] 3f ce [2] 30 d4 [2] 2e c9 [2] 2c c8 [2] 37 ce [2] 2b c9 [2] 37 e6 }

  condition:
    any of them
}