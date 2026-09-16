rule TTP_XOR_QUAD_CurrentVersionRun_a8a7 {
  strings:
    $key_a8a7 = { fb c8 [2] df c6 [2] f4 ea [2] da c8 [2] ce d3 [2] c1 c9 [2] df d4 [2] dd d5 [2] c6 d3 [2] da d4 [2] c6 fb }

  condition:
    any of them
}