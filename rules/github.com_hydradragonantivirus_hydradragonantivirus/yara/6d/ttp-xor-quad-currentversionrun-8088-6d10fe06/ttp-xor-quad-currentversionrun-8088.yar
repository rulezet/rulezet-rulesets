rule TTP_XOR_QUAD_CurrentVersionRun_8088 {
  strings:
    $key_8088 = { d3 e7 [2] f7 e9 [2] dc c5 [2] f2 e7 [2] e6 fc [2] e9 e6 [2] f7 fb [2] f5 fa [2] ee fc [2] f2 fb [2] ee d4 }

  condition:
    any of them
}