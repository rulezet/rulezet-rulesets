rule TTP_XOR_QUAD_CurrentVersionRun_f5af {
  strings:
    $key_f5af = { a6 c0 [2] 82 ce [2] a9 e2 [2] 87 c0 [2] 93 db [2] 9c c1 [2] 82 dc [2] 80 dd [2] 9b db [2] 87 dc [2] 9b f3 }

  condition:
    any of them
}