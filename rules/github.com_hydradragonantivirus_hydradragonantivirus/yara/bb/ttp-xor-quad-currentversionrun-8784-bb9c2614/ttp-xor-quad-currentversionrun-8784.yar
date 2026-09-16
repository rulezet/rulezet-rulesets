rule TTP_XOR_QUAD_CurrentVersionRun_8784 {
  strings:
    $key_8784 = { d4 eb [2] f0 e5 [2] db c9 [2] f5 eb [2] e1 f0 [2] ee ea [2] f0 f7 [2] f2 f6 [2] e9 f0 [2] f5 f7 [2] e9 d8 }

  condition:
    any of them
}