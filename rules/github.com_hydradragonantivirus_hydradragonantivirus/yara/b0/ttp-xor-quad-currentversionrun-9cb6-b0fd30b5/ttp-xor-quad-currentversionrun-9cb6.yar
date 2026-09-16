rule TTP_XOR_QUAD_CurrentVersionRun_9cb6 {
  strings:
    $key_9cb6 = { cf d9 [2] eb d7 [2] c0 fb [2] ee d9 [2] fa c2 [2] f5 d8 [2] eb c5 [2] e9 c4 [2] f2 c2 [2] ee c5 [2] f2 ea }

  condition:
    any of them
}