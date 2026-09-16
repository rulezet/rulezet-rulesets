rule TTP_XOR_QUAD_CurrentVersionRun_b1a9 {
  strings:
    $key_b1a9 = { e2 c6 [2] c6 c8 [2] ed e4 [2] c3 c6 [2] d7 dd [2] d8 c7 [2] c6 da [2] c4 db [2] df dd [2] c3 da [2] df f5 }

  condition:
    any of them
}