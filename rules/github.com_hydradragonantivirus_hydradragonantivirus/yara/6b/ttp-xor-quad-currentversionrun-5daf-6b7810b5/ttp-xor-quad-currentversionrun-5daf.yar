rule TTP_XOR_QUAD_CurrentVersionRun_5daf {
  strings:
    $key_5daf = { 0e c0 [2] 2a ce [2] 01 e2 [2] 2f c0 [2] 3b db [2] 34 c1 [2] 2a dc [2] 28 dd [2] 33 db [2] 2f dc [2] 33 f3 }

  condition:
    any of them
}