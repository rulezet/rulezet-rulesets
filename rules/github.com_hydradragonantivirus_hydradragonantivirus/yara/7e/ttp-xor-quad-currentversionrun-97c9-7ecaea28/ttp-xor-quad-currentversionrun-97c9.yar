rule TTP_XOR_QUAD_CurrentVersionRun_97c9 {
  strings:
    $key_97c9 = { c4 a6 [2] e0 a8 [2] cb 84 [2] e5 a6 [2] f1 bd [2] fe a7 [2] e0 ba [2] e2 bb [2] f9 bd [2] e5 ba [2] f9 95 }

  condition:
    any of them
}