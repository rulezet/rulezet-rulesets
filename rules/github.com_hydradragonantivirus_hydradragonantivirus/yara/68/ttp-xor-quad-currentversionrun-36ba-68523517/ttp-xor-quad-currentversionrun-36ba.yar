rule TTP_XOR_QUAD_CurrentVersionRun_36ba {
  strings:
    $key_36ba = { 65 d5 [2] 41 db [2] 6a f7 [2] 44 d5 [2] 50 ce [2] 5f d4 [2] 41 c9 [2] 43 c8 [2] 58 ce [2] 44 c9 [2] 58 e6 }

  condition:
    any of them
}