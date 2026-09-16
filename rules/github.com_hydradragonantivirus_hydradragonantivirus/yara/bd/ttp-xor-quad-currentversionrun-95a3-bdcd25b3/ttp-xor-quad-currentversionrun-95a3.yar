rule TTP_XOR_QUAD_CurrentVersionRun_95a3 {
  strings:
    $key_95a3 = { c6 cc [2] e2 c2 [2] c9 ee [2] e7 cc [2] f3 d7 [2] fc cd [2] e2 d0 [2] e0 d1 [2] fb d7 [2] e7 d0 [2] fb ff }

  condition:
    any of them
}