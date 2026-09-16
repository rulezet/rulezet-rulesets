rule TTP_XOR_QUAD_CurrentVersionRun_9c9f {
  strings:
    $key_9c9f = { cf f0 [2] eb fe [2] c0 d2 [2] ee f0 [2] fa eb [2] f5 f1 [2] eb ec [2] e9 ed [2] f2 eb [2] ee ec [2] f2 c3 }

  condition:
    any of them
}