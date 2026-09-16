rule TTP_XOR_QUAD_CurrentVersionRun_4dba {
  strings:
    $key_4dba = { 1e d5 [2] 3a db [2] 11 f7 [2] 3f d5 [2] 2b ce [2] 24 d4 [2] 3a c9 [2] 38 c8 [2] 23 ce [2] 3f c9 [2] 23 e6 }

  condition:
    any of them
}