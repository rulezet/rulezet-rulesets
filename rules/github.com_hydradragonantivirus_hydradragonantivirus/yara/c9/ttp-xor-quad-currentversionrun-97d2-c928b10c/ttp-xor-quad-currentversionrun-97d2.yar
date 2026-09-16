rule TTP_XOR_QUAD_CurrentVersionRun_97d2 {
  strings:
    $key_97d2 = { c4 bd [2] e0 b3 [2] cb 9f [2] e5 bd [2] f1 a6 [2] fe bc [2] e0 a1 [2] e2 a0 [2] f9 a6 [2] e5 a1 [2] f9 8e }

  condition:
    any of them
}