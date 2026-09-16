rule TTP_XOR_QUAD_CurrentVersionRun_9c93 {
  strings:
    $key_9c93 = { cf fc [2] eb f2 [2] c0 de [2] ee fc [2] fa e7 [2] f5 fd [2] eb e0 [2] e9 e1 [2] f2 e7 [2] ee e0 [2] f2 cf }

  condition:
    any of them
}