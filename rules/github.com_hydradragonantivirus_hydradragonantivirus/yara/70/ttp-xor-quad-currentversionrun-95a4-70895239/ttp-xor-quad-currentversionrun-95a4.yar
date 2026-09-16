rule TTP_XOR_QUAD_CurrentVersionRun_95a4 {
  strings:
    $key_95a4 = { c6 cb [2] e2 c5 [2] c9 e9 [2] e7 cb [2] f3 d0 [2] fc ca [2] e2 d7 [2] e0 d6 [2] fb d0 [2] e7 d7 [2] fb f8 }

  condition:
    any of them
}