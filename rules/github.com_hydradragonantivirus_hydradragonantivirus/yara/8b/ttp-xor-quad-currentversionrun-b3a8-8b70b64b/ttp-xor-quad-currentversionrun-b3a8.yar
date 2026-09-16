rule TTP_XOR_QUAD_CurrentVersionRun_b3a8 {
  strings:
    $key_b3a8 = { e0 c7 [2] c4 c9 [2] ef e5 [2] c1 c7 [2] d5 dc [2] da c6 [2] c4 db [2] c6 da [2] dd dc [2] c1 db [2] dd f4 }

  condition:
    any of them
}