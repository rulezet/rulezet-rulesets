rule TTP_XOR_QUAD_CurrentVersionRun_2eba {
  strings:
    $key_2eba = { 7d d5 [2] 59 db [2] 72 f7 [2] 5c d5 [2] 48 ce [2] 47 d4 [2] 59 c9 [2] 5b c8 [2] 40 ce [2] 5c c9 [2] 40 e6 }

  condition:
    any of them
}