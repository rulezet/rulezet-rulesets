rule TTP_XOR_QUAD_CurrentVersionRun_9c98 {
  strings:
    $key_9c98 = { cf f7 [2] eb f9 [2] c0 d5 [2] ee f7 [2] fa ec [2] f5 f6 [2] eb eb [2] e9 ea [2] f2 ec [2] ee eb [2] f2 c4 }

  condition:
    any of them
}