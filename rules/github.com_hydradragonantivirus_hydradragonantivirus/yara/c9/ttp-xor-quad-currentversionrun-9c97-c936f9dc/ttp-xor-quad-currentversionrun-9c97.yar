rule TTP_XOR_QUAD_CurrentVersionRun_9c97 {
  strings:
    $key_9c97 = { cf f8 [2] eb f6 [2] c0 da [2] ee f8 [2] fa e3 [2] f5 f9 [2] eb e4 [2] e9 e5 [2] f2 e3 [2] ee e4 [2] f2 cb }

  condition:
    any of them
}