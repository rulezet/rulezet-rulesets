rule TTP_XOR_QUAD_CurrentVersionRun_09ba {
  strings:
    $key_09ba = { 5a d5 [2] 7e db [2] 55 f7 [2] 7b d5 [2] 6f ce [2] 60 d4 [2] 7e c9 [2] 7c c8 [2] 67 ce [2] 7b c9 [2] 67 e6 }

  condition:
    any of them
}