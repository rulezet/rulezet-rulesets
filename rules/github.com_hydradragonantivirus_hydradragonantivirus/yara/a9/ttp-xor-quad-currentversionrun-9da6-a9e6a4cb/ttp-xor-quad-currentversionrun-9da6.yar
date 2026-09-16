rule TTP_XOR_QUAD_CurrentVersionRun_9da6 {
  strings:
    $key_9da6 = { ce c9 [2] ea c7 [2] c1 eb [2] ef c9 [2] fb d2 [2] f4 c8 [2] ea d5 [2] e8 d4 [2] f3 d2 [2] ef d5 [2] f3 fa }

  condition:
    any of them
}