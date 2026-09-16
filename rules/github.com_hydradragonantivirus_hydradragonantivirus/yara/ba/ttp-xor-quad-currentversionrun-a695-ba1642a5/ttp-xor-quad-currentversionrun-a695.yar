rule TTP_XOR_QUAD_CurrentVersionRun_a695 {
  strings:
    $key_a695 = { f5 fa [2] d1 f4 [2] fa d8 [2] d4 fa [2] c0 e1 [2] cf fb [2] d1 e6 [2] d3 e7 [2] c8 e1 [2] d4 e6 [2] c8 c9 }

  condition:
    any of them
}