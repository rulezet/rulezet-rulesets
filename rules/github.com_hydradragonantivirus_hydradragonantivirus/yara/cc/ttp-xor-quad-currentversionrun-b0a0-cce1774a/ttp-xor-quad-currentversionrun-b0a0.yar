rule TTP_XOR_QUAD_CurrentVersionRun_b0a0 {
  strings:
    $key_b0a0 = { e3 cf [2] c7 c1 [2] ec ed [2] c2 cf [2] d6 d4 [2] d9 ce [2] c7 d3 [2] c5 d2 [2] de d4 [2] c2 d3 [2] de fc }

  condition:
    any of them
}