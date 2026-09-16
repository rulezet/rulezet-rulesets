rule TTP_XOR_QUAD_CurrentVersionRun_0fba {
  strings:
    $key_0fba = { 5c d5 [2] 78 db [2] 53 f7 [2] 7d d5 [2] 69 ce [2] 66 d4 [2] 78 c9 [2] 7a c8 [2] 61 ce [2] 7d c9 [2] 61 e6 }

  condition:
    any of them
}