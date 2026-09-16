rule TTP_XOR_QUAD_CurrentVersionRun_97a9 {
  strings:
    $key_97a9 = { c4 c6 [2] e0 c8 [2] cb e4 [2] e5 c6 [2] f1 dd [2] fe c7 [2] e0 da [2] e2 db [2] f9 dd [2] e5 da [2] f9 f5 }

  condition:
    any of them
}