rule TTP_XOR_QUAD_CurrentVersionRun_f0af {
  strings:
    $key_f0af = { a3 c0 [2] 87 ce [2] ac e2 [2] 82 c0 [2] 96 db [2] 99 c1 [2] 87 dc [2] 85 dd [2] 9e db [2] 82 dc [2] 9e f3 }

  condition:
    any of them
}