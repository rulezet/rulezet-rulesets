rule TTP_XOR_QUAD_CurrentVersionRun_97c8 {
  strings:
    $key_97c8 = { c4 a7 [2] e0 a9 [2] cb 85 [2] e5 a7 [2] f1 bc [2] fe a6 [2] e0 bb [2] e2 ba [2] f9 bc [2] e5 bb [2] f9 94 }

  condition:
    any of them
}