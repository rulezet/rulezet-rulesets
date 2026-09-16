rule TTP_XOR_QUAD_CurrentVersionRun_52ba {
  strings:
    $key_52ba = { 01 d5 [2] 25 db [2] 0e f7 [2] 20 d5 [2] 34 ce [2] 3b d4 [2] 25 c9 [2] 27 c8 [2] 3c ce [2] 20 c9 [2] 3c e6 }

  condition:
    any of them
}