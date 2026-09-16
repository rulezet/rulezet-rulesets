rule TTP_XOR_QUAD_CurrentVersionRun_97a1 {
  strings:
    $key_97a1 = { c4 ce [2] e0 c0 [2] cb ec [2] e5 ce [2] f1 d5 [2] fe cf [2] e0 d2 [2] e2 d3 [2] f9 d5 [2] e5 d2 [2] f9 fd }

  condition:
    any of them
}