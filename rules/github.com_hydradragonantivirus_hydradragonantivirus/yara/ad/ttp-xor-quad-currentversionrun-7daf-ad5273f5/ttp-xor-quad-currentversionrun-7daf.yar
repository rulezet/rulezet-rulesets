rule TTP_XOR_QUAD_CurrentVersionRun_7daf {
  strings:
    $key_7daf = { 2e c0 [2] 0a ce [2] 21 e2 [2] 0f c0 [2] 1b db [2] 14 c1 [2] 0a dc [2] 08 dd [2] 13 db [2] 0f dc [2] 13 f3 }

  condition:
    any of them
}