rule TTP_XOR_QUAD_CurrentVersionRun_97f7 {
  strings:
    $key_97f7 = { c4 98 [2] e0 96 [2] cb ba [2] e5 98 [2] f1 83 [2] fe 99 [2] e0 84 [2] e2 85 [2] f9 83 [2] e5 84 [2] f9 ab }

  condition:
    any of them
}