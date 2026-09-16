rule TTP_XOR_QUAD_CurrentVersionRun_64af {
  strings:
    $key_64af = { 37 c0 [2] 13 ce [2] 38 e2 [2] 16 c0 [2] 02 db [2] 0d c1 [2] 13 dc [2] 11 dd [2] 0a db [2] 16 dc [2] 0a f3 }

  condition:
    any of them
}