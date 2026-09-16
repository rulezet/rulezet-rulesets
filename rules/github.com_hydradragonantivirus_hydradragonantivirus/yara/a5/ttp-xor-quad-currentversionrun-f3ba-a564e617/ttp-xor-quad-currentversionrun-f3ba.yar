rule TTP_XOR_QUAD_CurrentVersionRun_f3ba {
  strings:
    $key_f3ba = { a0 d5 [2] 84 db [2] af f7 [2] 81 d5 [2] 95 ce [2] 9a d4 [2] 84 c9 [2] 86 c8 [2] 9d ce [2] 81 c9 [2] 9d e6 }

  condition:
    any of them
}