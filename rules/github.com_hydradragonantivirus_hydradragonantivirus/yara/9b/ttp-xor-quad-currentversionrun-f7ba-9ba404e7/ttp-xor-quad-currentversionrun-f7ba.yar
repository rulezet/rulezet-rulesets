rule TTP_XOR_QUAD_CurrentVersionRun_f7ba {
  strings:
    $key_f7ba = { a4 d5 [2] 80 db [2] ab f7 [2] 85 d5 [2] 91 ce [2] 9e d4 [2] 80 c9 [2] 82 c8 [2] 99 ce [2] 85 c9 [2] 99 e6 }

  condition:
    any of them
}