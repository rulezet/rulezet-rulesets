rule TTP_XOR_QUAD_CurrentVersionRun_b0a7 {
  strings:
    $key_b0a7 = { e3 c8 [2] c7 c6 [2] ec ea [2] c2 c8 [2] d6 d3 [2] d9 c9 [2] c7 d4 [2] c5 d5 [2] de d3 [2] c2 d4 [2] de fb }

  condition:
    any of them
}