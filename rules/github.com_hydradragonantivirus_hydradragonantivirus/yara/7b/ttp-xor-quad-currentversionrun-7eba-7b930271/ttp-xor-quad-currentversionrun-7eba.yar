rule TTP_XOR_QUAD_CurrentVersionRun_7eba {
  strings:
    $key_7eba = { 2d d5 [2] 09 db [2] 22 f7 [2] 0c d5 [2] 18 ce [2] 17 d4 [2] 09 c9 [2] 0b c8 [2] 10 ce [2] 0c c9 [2] 10 e6 }

  condition:
    any of them
}