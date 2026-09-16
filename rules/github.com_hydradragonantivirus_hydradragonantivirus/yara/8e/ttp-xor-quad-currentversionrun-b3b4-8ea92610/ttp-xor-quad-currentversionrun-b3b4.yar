rule TTP_XOR_QUAD_CurrentVersionRun_b3b4 {
  strings:
    $key_b3b4 = { e0 db [2] c4 d5 [2] ef f9 [2] c1 db [2] d5 c0 [2] da da [2] c4 c7 [2] c6 c6 [2] dd c0 [2] c1 c7 [2] dd e8 }

  condition:
    any of them
}