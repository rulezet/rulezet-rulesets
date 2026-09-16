rule TTP_XOR_QUAD_CurrentVersionRun_95a9 {
  strings:
    $key_95a9 = { c6 c6 [2] e2 c8 [2] c9 e4 [2] e7 c6 [2] f3 dd [2] fc c7 [2] e2 da [2] e0 db [2] fb dd [2] e7 da [2] fb f5 }

  condition:
    any of them
}