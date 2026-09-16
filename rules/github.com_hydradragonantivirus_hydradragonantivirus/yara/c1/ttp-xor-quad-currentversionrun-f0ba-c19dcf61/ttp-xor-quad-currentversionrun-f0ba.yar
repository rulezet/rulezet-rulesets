rule TTP_XOR_QUAD_CurrentVersionRun_f0ba {
  strings:
    $key_f0ba = { a3 d5 [2] 87 db [2] ac f7 [2] 82 d5 [2] 96 ce [2] 99 d4 [2] 87 c9 [2] 85 c8 [2] 9e ce [2] 82 c9 [2] 9e e6 }

  condition:
    any of them
}