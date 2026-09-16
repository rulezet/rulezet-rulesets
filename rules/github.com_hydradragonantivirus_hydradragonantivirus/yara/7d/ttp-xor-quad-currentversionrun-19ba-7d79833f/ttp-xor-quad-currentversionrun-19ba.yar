rule TTP_XOR_QUAD_CurrentVersionRun_19ba {
  strings:
    $key_19ba = { 4a d5 [2] 6e db [2] 45 f7 [2] 6b d5 [2] 7f ce [2] 70 d4 [2] 6e c9 [2] 6c c8 [2] 77 ce [2] 6b c9 [2] 77 e6 }

  condition:
    any of them
}