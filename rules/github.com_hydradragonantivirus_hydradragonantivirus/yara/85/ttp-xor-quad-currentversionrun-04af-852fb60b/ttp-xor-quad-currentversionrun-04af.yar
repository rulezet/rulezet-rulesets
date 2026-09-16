rule TTP_XOR_QUAD_CurrentVersionRun_04af {
  strings:
    $key_04af = { 57 c0 [2] 73 ce [2] 58 e2 [2] 76 c0 [2] 62 db [2] 6d c1 [2] 73 dc [2] 71 dd [2] 6a db [2] 76 dc [2] 6a f3 }

  condition:
    any of them
}