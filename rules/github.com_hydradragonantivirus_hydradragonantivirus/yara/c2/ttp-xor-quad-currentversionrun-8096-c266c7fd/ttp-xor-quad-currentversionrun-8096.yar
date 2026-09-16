rule TTP_XOR_QUAD_CurrentVersionRun_8096 {
  strings:
    $key_8096 = { d3 f9 [2] f7 f7 [2] dc db [2] f2 f9 [2] e6 e2 [2] e9 f8 [2] f7 e5 [2] f5 e4 [2] ee e2 [2] f2 e5 [2] ee ca }

  condition:
    any of them
}