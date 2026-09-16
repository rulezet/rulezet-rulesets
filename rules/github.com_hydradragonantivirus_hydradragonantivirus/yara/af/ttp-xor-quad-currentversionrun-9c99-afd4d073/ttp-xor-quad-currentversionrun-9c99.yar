rule TTP_XOR_QUAD_CurrentVersionRun_9c99 {
  strings:
    $key_9c99 = { cf f6 [2] eb f8 [2] c0 d4 [2] ee f6 [2] fa ed [2] f5 f7 [2] eb ea [2] e9 eb [2] f2 ed [2] ee ea [2] f2 c5 }

  condition:
    any of them
}