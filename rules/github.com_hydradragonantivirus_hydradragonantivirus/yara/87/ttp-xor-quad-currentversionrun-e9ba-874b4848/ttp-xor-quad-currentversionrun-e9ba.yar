rule TTP_XOR_QUAD_CurrentVersionRun_e9ba {
  strings:
    $key_e9ba = { ba d5 [2] 9e db [2] b5 f7 [2] 9b d5 [2] 8f ce [2] 80 d4 [2] 9e c9 [2] 9c c8 [2] 87 ce [2] 9b c9 [2] 87 e6 }

  condition:
    any of them
}