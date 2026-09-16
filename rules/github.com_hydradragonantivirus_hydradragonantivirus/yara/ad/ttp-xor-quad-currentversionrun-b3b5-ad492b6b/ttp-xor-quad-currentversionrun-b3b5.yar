rule TTP_XOR_QUAD_CurrentVersionRun_b3b5 {
  strings:
    $key_b3b5 = { e0 da [2] c4 d4 [2] ef f8 [2] c1 da [2] d5 c1 [2] da db [2] c4 c6 [2] c6 c7 [2] dd c1 [2] c1 c6 [2] dd e9 }

  condition:
    any of them
}