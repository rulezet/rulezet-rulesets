rule TTP_XOR_QUAD_CurrentVersionRun_3dba {
  strings:
    $key_3dba = { 6e d5 [2] 4a db [2] 61 f7 [2] 4f d5 [2] 5b ce [2] 54 d4 [2] 4a c9 [2] 48 c8 [2] 53 ce [2] 4f c9 [2] 53 e6 }

  condition:
    any of them
}