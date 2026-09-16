rule TTP_XOR_QUAD_CurrentVersionRun_97f1 {
  strings:
    $key_97f1 = { c4 9e [2] e0 90 [2] cb bc [2] e5 9e [2] f1 85 [2] fe 9f [2] e0 82 [2] e2 83 [2] f9 85 [2] e5 82 [2] f9 ad }

  condition:
    any of them
}