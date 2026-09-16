rule TTP_XOR_QUAD_CurrentVersionRun_95d3 {
  strings:
    $key_95d3 = { c6 bc [2] e2 b2 [2] c9 9e [2] e7 bc [2] f3 a7 [2] fc bd [2] e2 a0 [2] e0 a1 [2] fb a7 [2] e7 a0 [2] fb 8f }

  condition:
    any of them
}