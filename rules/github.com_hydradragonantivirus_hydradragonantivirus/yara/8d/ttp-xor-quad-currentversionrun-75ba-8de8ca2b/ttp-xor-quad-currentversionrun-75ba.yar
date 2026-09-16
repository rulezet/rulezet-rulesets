rule TTP_XOR_QUAD_CurrentVersionRun_75ba {
  strings:
    $key_75ba = { 26 d5 [2] 02 db [2] 29 f7 [2] 07 d5 [2] 13 ce [2] 1c d4 [2] 02 c9 [2] 00 c8 [2] 1b ce [2] 07 c9 [2] 1b e6 }

  condition:
    any of them
}