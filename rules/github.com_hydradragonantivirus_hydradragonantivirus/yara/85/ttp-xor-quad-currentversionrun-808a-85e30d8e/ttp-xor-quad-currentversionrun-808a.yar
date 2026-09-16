rule TTP_XOR_QUAD_CurrentVersionRun_808a {
  strings:
    $key_808a = { d3 e5 [2] f7 eb [2] dc c7 [2] f2 e5 [2] e6 fe [2] e9 e4 [2] f7 f9 [2] f5 f8 [2] ee fe [2] f2 f9 [2] ee d6 }

  condition:
    any of them
}