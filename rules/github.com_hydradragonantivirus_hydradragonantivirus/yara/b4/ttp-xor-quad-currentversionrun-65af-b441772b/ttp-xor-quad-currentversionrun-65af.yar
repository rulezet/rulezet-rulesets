rule TTP_XOR_QUAD_CurrentVersionRun_65af {
  strings:
    $key_65af = { 36 c0 [2] 12 ce [2] 39 e2 [2] 17 c0 [2] 03 db [2] 0c c1 [2] 12 dc [2] 10 dd [2] 0b db [2] 17 dc [2] 0b f3 }

  condition:
    any of them
}