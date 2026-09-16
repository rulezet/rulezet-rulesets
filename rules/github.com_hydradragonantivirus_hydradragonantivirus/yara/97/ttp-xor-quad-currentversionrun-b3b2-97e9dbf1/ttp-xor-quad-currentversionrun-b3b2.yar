rule TTP_XOR_QUAD_CurrentVersionRun_b3b2 {
  strings:
    $key_b3b2 = { e0 dd [2] c4 d3 [2] ef ff [2] c1 dd [2] d5 c6 [2] da dc [2] c4 c1 [2] c6 c0 [2] dd c6 [2] c1 c1 [2] dd ee }

  condition:
    any of them
}