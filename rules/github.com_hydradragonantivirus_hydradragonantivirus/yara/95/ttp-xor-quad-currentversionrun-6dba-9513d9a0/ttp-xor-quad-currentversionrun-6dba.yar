rule TTP_XOR_QUAD_CurrentVersionRun_6dba {
  strings:
    $key_6dba = { 3e d5 [2] 1a db [2] 31 f7 [2] 1f d5 [2] 0b ce [2] 04 d4 [2] 1a c9 [2] 18 c8 [2] 03 ce [2] 1f c9 [2] 03 e6 }

  condition:
    any of them
}