rule TTP_XOR_QUAD_CurrentVersionRun_9c91 {
  strings:
    $key_9c91 = { cf fe [2] eb f0 [2] c0 dc [2] ee fe [2] fa e5 [2] f5 ff [2] eb e2 [2] e9 e3 [2] f2 e5 [2] ee e2 [2] f2 cd }

  condition:
    any of them
}