rule TTP_XOR_QUAD_CurrentVersionRun_f5ba {
  strings:
    $key_f5ba = { a6 d5 [2] 82 db [2] a9 f7 [2] 87 d5 [2] 93 ce [2] 9c d4 [2] 82 c9 [2] 80 c8 [2] 9b ce [2] 87 c9 [2] 9b e6 }

  condition:
    any of them
}