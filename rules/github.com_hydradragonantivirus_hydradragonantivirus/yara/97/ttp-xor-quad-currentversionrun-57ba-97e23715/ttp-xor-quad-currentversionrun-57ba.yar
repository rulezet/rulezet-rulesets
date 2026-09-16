rule TTP_XOR_QUAD_CurrentVersionRun_57ba {
  strings:
    $key_57ba = { 04 d5 [2] 20 db [2] 0b f7 [2] 25 d5 [2] 31 ce [2] 3e d4 [2] 20 c9 [2] 22 c8 [2] 39 ce [2] 25 c9 [2] 39 e6 }

  condition:
    any of them
}