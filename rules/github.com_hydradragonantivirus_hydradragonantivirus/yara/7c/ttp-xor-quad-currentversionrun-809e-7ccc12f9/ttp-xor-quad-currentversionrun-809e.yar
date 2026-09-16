rule TTP_XOR_QUAD_CurrentVersionRun_809e {
  strings:
    $key_809e = { d3 f1 [2] f7 ff [2] dc d3 [2] f2 f1 [2] e6 ea [2] e9 f0 [2] f7 ed [2] f5 ec [2] ee ea [2] f2 ed [2] ee c2 }

  condition:
    any of them
}