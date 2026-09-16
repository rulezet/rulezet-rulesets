rule TTP_XOR_QUAD_CurrentVersionRun_a6b7 {
  strings:
    $key_a6b7 = { f5 d8 [2] d1 d6 [2] fa fa [2] d4 d8 [2] c0 c3 [2] cf d9 [2] d1 c4 [2] d3 c5 [2] c8 c3 [2] d4 c4 [2] c8 eb }

  condition:
    any of them
}