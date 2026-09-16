rule TTP_XOR_QUAD_CurrentVersionRun_f7af {
  strings:
    $key_f7af = { a4 c0 [2] 80 ce [2] ab e2 [2] 85 c0 [2] 91 db [2] 9e c1 [2] 80 dc [2] 82 dd [2] 99 db [2] 85 dc [2] 99 f3 }

  condition:
    any of them
}