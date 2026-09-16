rule TTP_XOR_QUAD_CurrentVersionRun_8089 {
  strings:
    $key_8089 = { d3 e6 [2] f7 e8 [2] dc c4 [2] f2 e6 [2] e6 fd [2] e9 e7 [2] f7 fa [2] f5 fb [2] ee fd [2] f2 fa [2] ee d5 }

  condition:
    any of them
}