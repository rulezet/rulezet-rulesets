rule TTP_XOR_QUAD_CurrentVersionRun_12ba {
  strings:
    $key_12ba = { 41 d5 [2] 65 db [2] 4e f7 [2] 60 d5 [2] 74 ce [2] 7b d4 [2] 65 c9 [2] 67 c8 [2] 7c ce [2] 60 c9 [2] 7c e6 }

  condition:
    any of them
}