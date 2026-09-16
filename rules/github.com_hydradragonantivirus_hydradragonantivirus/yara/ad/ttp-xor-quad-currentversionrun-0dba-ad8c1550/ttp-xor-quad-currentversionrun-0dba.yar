rule TTP_XOR_QUAD_CurrentVersionRun_0dba {
  strings:
    $key_0dba = { 5e d5 [2] 7a db [2] 51 f7 [2] 7f d5 [2] 6b ce [2] 64 d4 [2] 7a c9 [2] 78 c8 [2] 63 ce [2] 7f c9 [2] 63 e6 }

  condition:
    any of them
}