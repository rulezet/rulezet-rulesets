rule TTP_XOR_QUAD_CurrentVersionRun_80b4 {
  strings:
    $key_80b4 = { d3 db [2] f7 d5 [2] dc f9 [2] f2 db [2] e6 c0 [2] e9 da [2] f7 c7 [2] f5 c6 [2] ee c0 [2] f2 c7 [2] ee e8 }

  condition:
    any of them
}