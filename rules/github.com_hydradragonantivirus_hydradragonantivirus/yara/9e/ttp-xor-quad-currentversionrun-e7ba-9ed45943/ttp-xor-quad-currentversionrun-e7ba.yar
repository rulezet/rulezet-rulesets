rule TTP_XOR_QUAD_CurrentVersionRun_e7ba {
  strings:
    $key_e7ba = { b4 d5 [2] 90 db [2] bb f7 [2] 95 d5 [2] 81 ce [2] 8e d4 [2] 90 c9 [2] 92 c8 [2] 89 ce [2] 95 c9 [2] 89 e6 }

  condition:
    any of them
}