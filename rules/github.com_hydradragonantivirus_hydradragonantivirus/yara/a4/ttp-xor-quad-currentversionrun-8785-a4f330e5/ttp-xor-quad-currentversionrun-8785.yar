rule TTP_XOR_QUAD_CurrentVersionRun_8785 {
  strings:
    $key_8785 = { d4 ea [2] f0 e4 [2] db c8 [2] f5 ea [2] e1 f1 [2] ee eb [2] f0 f6 [2] f2 f7 [2] e9 f1 [2] f5 f6 [2] e9 d9 }

  condition:
    any of them
}