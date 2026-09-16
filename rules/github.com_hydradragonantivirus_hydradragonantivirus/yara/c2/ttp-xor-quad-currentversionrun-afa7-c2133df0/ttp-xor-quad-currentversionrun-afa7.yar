rule TTP_XOR_QUAD_CurrentVersionRun_afa7 {
  strings:
    $key_afa7 = { fc c8 [2] d8 c6 [2] f3 ea [2] dd c8 [2] c9 d3 [2] c6 c9 [2] d8 d4 [2] da d5 [2] c1 d3 [2] dd d4 [2] c1 fb }

  condition:
    any of them
}