rule TTP_XOR_QUAD_CurrentVersionRun_32ba {
  strings:
    $key_32ba = { 61 d5 [2] 45 db [2] 6e f7 [2] 40 d5 [2] 54 ce [2] 5b d4 [2] 45 c9 [2] 47 c8 [2] 5c ce [2] 40 c9 [2] 5c e6 }

  condition:
    any of them
}