rule TTP_XOR_QUAD_CurrentVersionRun_45af {
  strings:
    $key_45af = { 16 c0 [2] 32 ce [2] 19 e2 [2] 37 c0 [2] 23 db [2] 2c c1 [2] 32 dc [2] 30 dd [2] 2b db [2] 37 dc [2] 2b f3 }

  condition:
    any of them
}