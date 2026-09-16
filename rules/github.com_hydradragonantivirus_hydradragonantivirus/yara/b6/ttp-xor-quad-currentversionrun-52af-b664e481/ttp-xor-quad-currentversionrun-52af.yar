rule TTP_XOR_QUAD_CurrentVersionRun_52af {
  strings:
    $key_52af = { 01 c0 [2] 25 ce [2] 0e e2 [2] 20 c0 [2] 34 db [2] 3b c1 [2] 25 dc [2] 27 dd [2] 3c db [2] 20 dc [2] 3c f3 }

  condition:
    any of them
}