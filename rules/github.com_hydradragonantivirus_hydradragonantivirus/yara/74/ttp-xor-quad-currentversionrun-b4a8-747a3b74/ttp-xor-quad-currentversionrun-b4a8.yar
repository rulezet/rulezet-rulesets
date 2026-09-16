rule TTP_XOR_QUAD_CurrentVersionRun_b4a8 {
  strings:
    $key_b4a8 = { e7 c7 [2] c3 c9 [2] e8 e5 [2] c6 c7 [2] d2 dc [2] dd c6 [2] c3 db [2] c1 da [2] da dc [2] c6 db [2] da f4 }

  condition:
    any of them
}