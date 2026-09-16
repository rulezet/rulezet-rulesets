rule TTP_XOR_QUAD_CurrentVersionRun_2daf {
  strings:
    $key_2daf = { 7e c0 [2] 5a ce [2] 71 e2 [2] 5f c0 [2] 4b db [2] 44 c1 [2] 5a dc [2] 58 dd [2] 43 db [2] 5f dc [2] 43 f3 }

  condition:
    any of them
}