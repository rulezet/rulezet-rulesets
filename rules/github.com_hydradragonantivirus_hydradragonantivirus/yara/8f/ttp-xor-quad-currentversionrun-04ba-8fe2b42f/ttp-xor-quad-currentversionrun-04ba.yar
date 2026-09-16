rule TTP_XOR_QUAD_CurrentVersionRun_04ba {
  strings:
    $key_04ba = { 57 d5 [2] 73 db [2] 58 f7 [2] 76 d5 [2] 62 ce [2] 6d d4 [2] 73 c9 [2] 71 c8 [2] 6a ce [2] 76 c9 [2] 6a e6 }

  condition:
    any of them
}