rule TTP_XOR_QUAD_CurrentVersionRun_2fba {
  strings:
    $key_2fba = { 7c d5 [2] 58 db [2] 73 f7 [2] 5d d5 [2] 49 ce [2] 46 d4 [2] 58 c9 [2] 5a c8 [2] 41 ce [2] 5d c9 [2] 41 e6 }

  condition:
    any of them
}