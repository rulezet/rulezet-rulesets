rule TTP_XOR_QUAD_CurrentVersionRun_97d5 {
  strings:
    $key_97d5 = { c4 ba [2] e0 b4 [2] cb 98 [2] e5 ba [2] f1 a1 [2] fe bb [2] e0 a6 [2] e2 a7 [2] f9 a1 [2] e5 a6 [2] f9 89 }

  condition:
    any of them
}