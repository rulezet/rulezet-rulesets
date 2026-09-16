rule TTP_XOR_QUAD_CurrentVersionRun_80b3 {
  strings:
    $key_80b3 = { d3 dc [2] f7 d2 [2] dc fe [2] f2 dc [2] e6 c7 [2] e9 dd [2] f7 c0 [2] f5 c1 [2] ee c7 [2] f2 c0 [2] ee ef }

  condition:
    any of them
}