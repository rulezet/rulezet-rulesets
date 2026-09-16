rule TTP_XOR_QUAD_CurrentVersionRun_8085 {
  strings:
    $key_8085 = { d3 ea [2] f7 e4 [2] dc c8 [2] f2 ea [2] e6 f1 [2] e9 eb [2] f7 f6 [2] f5 f7 [2] ee f1 [2] f2 f6 [2] ee d9 }

  condition:
    any of them
}