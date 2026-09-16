rule TTP_XOR_QUAD_CurrentVersionRun_97b3 {
  strings:
    $key_97b3 = { c4 dc [2] e0 d2 [2] cb fe [2] e5 dc [2] f1 c7 [2] fe dd [2] e0 c0 [2] e2 c1 [2] f9 c7 [2] e5 c0 [2] f9 ef }

  condition:
    any of them
}