rule TTP_XOR_QUAD_CurrentVersionRun_9584 {
  strings:
    $key_9584 = { c6 eb [2] e2 e5 [2] c9 c9 [2] e7 eb [2] f3 f0 [2] fc ea [2] e2 f7 [2] e0 f6 [2] fb f0 [2] e7 f7 [2] fb d8 }

  condition:
    any of them
}