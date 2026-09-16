rule TTP_XOR_QUAD_CurrentVersionRun_66ba {
  strings:
    $key_66ba = { 35 d5 [2] 11 db [2] 3a f7 [2] 14 d5 [2] 00 ce [2] 0f d4 [2] 11 c9 [2] 13 c8 [2] 08 ce [2] 14 c9 [2] 08 e6 }

  condition:
    any of them
}