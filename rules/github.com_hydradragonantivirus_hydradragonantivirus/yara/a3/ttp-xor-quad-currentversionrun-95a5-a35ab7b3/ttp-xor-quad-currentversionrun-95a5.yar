rule TTP_XOR_QUAD_CurrentVersionRun_95a5 {
  strings:
    $key_95a5 = { c6 ca [2] e2 c4 [2] c9 e8 [2] e7 ca [2] f3 d1 [2] fc cb [2] e2 d6 [2] e0 d7 [2] fb d1 [2] e7 d6 [2] fb f9 }

  condition:
    any of them
}