rule TTP_XOR_QUAD_CurrentVersionRun_1eba {
  strings:
    $key_1eba = { 4d d5 [2] 69 db [2] 42 f7 [2] 6c d5 [2] 78 ce [2] 77 d4 [2] 69 c9 [2] 6b c8 [2] 70 ce [2] 6c c9 [2] 70 e6 }

  condition:
    any of them
}