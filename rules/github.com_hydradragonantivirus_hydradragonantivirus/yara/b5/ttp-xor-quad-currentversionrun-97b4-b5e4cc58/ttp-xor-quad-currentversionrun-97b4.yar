rule TTP_XOR_QUAD_CurrentVersionRun_97b4 {
  strings:
    $key_97b4 = { c4 db [2] e0 d5 [2] cb f9 [2] e5 db [2] f1 c0 [2] fe da [2] e0 c7 [2] e2 c6 [2] f9 c0 [2] e5 c7 [2] f9 e8 }

  condition:
    any of them
}