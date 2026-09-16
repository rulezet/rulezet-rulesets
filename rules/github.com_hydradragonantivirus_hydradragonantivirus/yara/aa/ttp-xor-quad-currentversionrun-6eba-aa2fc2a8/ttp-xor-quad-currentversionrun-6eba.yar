rule TTP_XOR_QUAD_CurrentVersionRun_6eba {
  strings:
    $key_6eba = { 3d d5 [2] 19 db [2] 32 f7 [2] 1c d5 [2] 08 ce [2] 07 d4 [2] 19 c9 [2] 1b c8 [2] 00 ce [2] 1c c9 [2] 00 e6 }

  condition:
    any of them
}