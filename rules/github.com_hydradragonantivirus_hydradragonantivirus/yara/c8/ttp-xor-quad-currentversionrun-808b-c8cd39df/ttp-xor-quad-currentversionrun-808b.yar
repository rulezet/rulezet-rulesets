rule TTP_XOR_QUAD_CurrentVersionRun_808b {
  strings:
    $key_808b = { d3 e4 [2] f7 ea [2] dc c6 [2] f2 e4 [2] e6 ff [2] e9 e5 [2] f7 f8 [2] f5 f9 [2] ee ff [2] f2 f8 [2] ee d7 }

  condition:
    any of them
}