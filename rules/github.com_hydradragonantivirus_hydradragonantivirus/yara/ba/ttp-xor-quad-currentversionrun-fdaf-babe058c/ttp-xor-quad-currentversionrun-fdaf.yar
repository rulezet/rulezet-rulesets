rule TTP_XOR_QUAD_CurrentVersionRun_fdaf {
  strings:
    $key_fdaf = { ae c0 [2] 8a ce [2] a1 e2 [2] 8f c0 [2] 9b db [2] 94 c1 [2] 8a dc [2] 88 dd [2] 93 db [2] 8f dc [2] 93 f3 }

  condition:
    any of them
}