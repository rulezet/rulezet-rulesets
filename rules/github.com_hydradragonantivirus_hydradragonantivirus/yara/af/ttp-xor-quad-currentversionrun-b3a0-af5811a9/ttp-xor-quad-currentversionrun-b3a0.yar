rule TTP_XOR_QUAD_CurrentVersionRun_b3a0 {
  strings:
    $key_b3a0 = { e0 cf [2] c4 c1 [2] ef ed [2] c1 cf [2] d5 d4 [2] da ce [2] c4 d3 [2] c6 d2 [2] dd d4 [2] c1 d3 [2] dd fc }

  condition:
    any of them
}