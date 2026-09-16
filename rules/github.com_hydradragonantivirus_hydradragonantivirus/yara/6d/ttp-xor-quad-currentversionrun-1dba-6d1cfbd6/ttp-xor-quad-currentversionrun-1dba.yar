rule TTP_XOR_QUAD_CurrentVersionRun_1dba {
  strings:
    $key_1dba = { 4e d5 [2] 6a db [2] 41 f7 [2] 6f d5 [2] 7b ce [2] 74 d4 [2] 6a c9 [2] 68 c8 [2] 73 ce [2] 6f c9 [2] 73 e6 }

  condition:
    any of them
}