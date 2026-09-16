rule TTP_XOR_QUAD_CurrentVersionRun_3daf {
  strings:
    $key_3daf = { 6e c0 [2] 4a ce [2] 61 e2 [2] 4f c0 [2] 5b db [2] 54 c1 [2] 4a dc [2] 48 dd [2] 53 db [2] 4f dc [2] 53 f3 }

  condition:
    any of them
}