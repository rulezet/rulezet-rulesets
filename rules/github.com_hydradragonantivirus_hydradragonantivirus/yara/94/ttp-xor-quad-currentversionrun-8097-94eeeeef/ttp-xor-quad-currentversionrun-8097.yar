rule TTP_XOR_QUAD_CurrentVersionRun_8097 {
  strings:
    $key_8097 = { d3 f8 [2] f7 f6 [2] dc da [2] f2 f8 [2] e6 e3 [2] e9 f9 [2] f7 e4 [2] f5 e5 [2] ee e3 [2] f2 e4 [2] ee cb }

  condition:
    any of them
}