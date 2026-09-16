rule TTP_XOR_QUAD_CurrentVersionRun_80b2 {
  strings:
    $key_80b2 = { d3 dd [2] f7 d3 [2] dc ff [2] f2 dd [2] e6 c6 [2] e9 dc [2] f7 c1 [2] f5 c0 [2] ee c6 [2] f2 c1 [2] ee ee }

  condition:
    any of them
}