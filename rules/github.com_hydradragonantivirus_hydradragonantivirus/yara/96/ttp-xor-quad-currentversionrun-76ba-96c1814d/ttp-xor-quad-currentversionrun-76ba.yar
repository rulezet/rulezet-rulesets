rule TTP_XOR_QUAD_CurrentVersionRun_76ba {
  strings:
    $key_76ba = { 25 d5 [2] 01 db [2] 2a f7 [2] 04 d5 [2] 10 ce [2] 1f d4 [2] 01 c9 [2] 03 c8 [2] 18 ce [2] 04 c9 [2] 18 e6 }

  condition:
    any of them
}