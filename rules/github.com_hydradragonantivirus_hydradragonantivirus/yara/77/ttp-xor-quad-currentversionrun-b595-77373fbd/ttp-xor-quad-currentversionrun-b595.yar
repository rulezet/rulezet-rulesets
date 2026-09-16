rule TTP_XOR_QUAD_CurrentVersionRun_b595 {
  strings:
    $key_b595 = { e6 fa [2] c2 f4 [2] e9 d8 [2] c7 fa [2] d3 e1 [2] dc fb [2] c2 e6 [2] c0 e7 [2] db e1 [2] c7 e6 [2] db c9 }

  condition:
    any of them
}