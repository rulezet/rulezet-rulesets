rule TTP_XOR_QUAD_CurrentVersionRun_97d6 {
  strings:
    $key_97d6 = { c4 b9 [2] e0 b7 [2] cb 9b [2] e5 b9 [2] f1 a2 [2] fe b8 [2] e0 a5 [2] e2 a4 [2] f9 a2 [2] e5 a5 [2] f9 8a }

  condition:
    any of them
}