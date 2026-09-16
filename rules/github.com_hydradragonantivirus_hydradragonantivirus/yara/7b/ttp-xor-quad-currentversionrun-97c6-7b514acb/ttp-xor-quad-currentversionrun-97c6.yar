rule TTP_XOR_QUAD_CurrentVersionRun_97c6 {
  strings:
    $key_97c6 = { c4 a9 [2] e0 a7 [2] cb 8b [2] e5 a9 [2] f1 b2 [2] fe a8 [2] e0 b5 [2] e2 b4 [2] f9 b2 [2] e5 b5 [2] f9 9a }

  condition:
    any of them
}