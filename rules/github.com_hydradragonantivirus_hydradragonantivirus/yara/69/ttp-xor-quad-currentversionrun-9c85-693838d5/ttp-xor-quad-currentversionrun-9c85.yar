rule TTP_XOR_QUAD_CurrentVersionRun_9c85 {
  strings:
    $key_9c85 = { cf ea [2] eb e4 [2] c0 c8 [2] ee ea [2] fa f1 [2] f5 eb [2] eb f6 [2] e9 f7 [2] f2 f1 [2] ee f6 [2] f2 d9 }

  condition:
    any of them
}