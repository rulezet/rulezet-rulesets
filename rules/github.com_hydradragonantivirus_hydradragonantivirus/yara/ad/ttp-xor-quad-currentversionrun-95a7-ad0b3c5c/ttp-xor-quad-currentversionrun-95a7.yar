rule TTP_XOR_QUAD_CurrentVersionRun_95a7 {
  strings:
    $key_95a7 = { c6 c8 [2] e2 c6 [2] c9 ea [2] e7 c8 [2] f3 d3 [2] fc c9 [2] e2 d4 [2] e0 d5 [2] fb d3 [2] e7 d4 [2] fb fb }

  condition:
    any of them
}