rule TTP_XOR_QUAD_CurrentVersionRun_7fba {
  strings:
    $key_7fba = { 2c d5 [2] 08 db [2] 23 f7 [2] 0d d5 [2] 19 ce [2] 16 d4 [2] 08 c9 [2] 0a c8 [2] 11 ce [2] 0d c9 [2] 11 e6 }

  condition:
    any of them
}