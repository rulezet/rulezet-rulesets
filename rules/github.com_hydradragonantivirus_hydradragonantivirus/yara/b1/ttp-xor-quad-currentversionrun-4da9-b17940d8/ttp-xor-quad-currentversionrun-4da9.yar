rule TTP_XOR_QUAD_CurrentVersionRun_4da9 {
  strings:
    $key_4da9 = { 1e c6 [2] 3a c8 [2] 11 e4 [2] 3f c6 [2] 2b dd [2] 24 c7 [2] 3a da [2] 38 db [2] 23 dd [2] 3f da [2] 23 f5 }

  condition:
    any of them
}