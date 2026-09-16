rule TTP_XOR_QUAD_CurrentVersionRun_46ba {
  strings:
    $key_46ba = { 15 d5 [2] 31 db [2] 1a f7 [2] 34 d5 [2] 20 ce [2] 2f d4 [2] 31 c9 [2] 33 c8 [2] 28 ce [2] 34 c9 [2] 28 e6 }

  condition:
    any of them
}