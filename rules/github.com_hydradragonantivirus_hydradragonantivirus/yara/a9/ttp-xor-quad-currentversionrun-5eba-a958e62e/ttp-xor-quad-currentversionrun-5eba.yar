rule TTP_XOR_QUAD_CurrentVersionRun_5eba {
  strings:
    $key_5eba = { 0d d5 [2] 29 db [2] 02 f7 [2] 2c d5 [2] 38 ce [2] 37 d4 [2] 29 c9 [2] 2b c8 [2] 30 ce [2] 2c c9 [2] 30 e6 }

  condition:
    any of them
}