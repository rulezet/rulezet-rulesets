rule TTP_XOR_QUAD_CurrentVersionRun_25af {
  strings:
    $key_25af = { 76 c0 [2] 52 ce [2] 79 e2 [2] 57 c0 [2] 43 db [2] 4c c1 [2] 52 dc [2] 50 dd [2] 4b db [2] 57 dc [2] 4b f3 }

  condition:
    any of them
}