rule TTP_XOR_QUAD_CurrentVersionRun_80a6 {
  strings:
    $key_80a6 = { d3 c9 [2] f7 c7 [2] dc eb [2] f2 c9 [2] e6 d2 [2] e9 c8 [2] f7 d5 [2] f5 d4 [2] ee d2 [2] f2 d5 [2] ee fa }

  condition:
    any of them
}