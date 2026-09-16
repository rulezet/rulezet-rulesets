rule TTP_XOR_QUAD_CurrentVersionRun_97d3 {
  strings:
    $key_97d3 = { c4 bc [2] e0 b2 [2] cb 9e [2] e5 bc [2] f1 a7 [2] fe bd [2] e0 a0 [2] e2 a1 [2] f9 a7 [2] e5 a0 [2] f9 8f }

  condition:
    any of them
}