rule TTP_XOR_QUAD_CurrentVersionRun_b5b5 {
  strings:
    $key_b5b5 = { e6 da [2] c2 d4 [2] e9 f8 [2] c7 da [2] d3 c1 [2] dc db [2] c2 c6 [2] c0 c7 [2] db c1 [2] c7 c6 [2] db e9 }

  condition:
    any of them
}