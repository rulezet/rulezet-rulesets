rule TTP_XOR_QUAD_CurrentVersionRun_4daf {
  strings:
    $key_4daf = { 1e c0 [2] 3a ce [2] 11 e2 [2] 3f c0 [2] 2b db [2] 24 c1 [2] 3a dc [2] 38 dd [2] 23 db [2] 3f dc [2] 23 f3 }

  condition:
    any of them
}