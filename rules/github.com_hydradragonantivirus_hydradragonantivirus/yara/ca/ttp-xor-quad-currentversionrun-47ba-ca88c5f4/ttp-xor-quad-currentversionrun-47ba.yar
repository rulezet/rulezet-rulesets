rule TTP_XOR_QUAD_CurrentVersionRun_47ba {
  strings:
    $key_47ba = { 14 d5 [2] 30 db [2] 1b f7 [2] 35 d5 [2] 21 ce [2] 2e d4 [2] 30 c9 [2] 32 c8 [2] 29 ce [2] 35 c9 [2] 29 e6 }

  condition:
    any of them
}