rule TTP_XOR_QUAD_CurrentVersionRun_6daf {
  strings:
    $key_6daf = { 3e c0 [2] 1a ce [2] 31 e2 [2] 1f c0 [2] 0b db [2] 04 c1 [2] 1a dc [2] 18 dd [2] 03 db [2] 1f dc [2] 03 f3 }

  condition:
    any of them
}