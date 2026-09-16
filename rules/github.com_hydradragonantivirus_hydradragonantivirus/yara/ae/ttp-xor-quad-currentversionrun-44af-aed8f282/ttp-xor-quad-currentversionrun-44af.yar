rule TTP_XOR_QUAD_CurrentVersionRun_44af {
  strings:
    $key_44af = { 17 c0 [2] 33 ce [2] 18 e2 [2] 36 c0 [2] 22 db [2] 2d c1 [2] 33 dc [2] 31 dd [2] 2a db [2] 36 dc [2] 2a f3 }

  condition:
    any of them
}