rule TTP_XOR_QUAD_CurrentVersionRun_b6a7 {
  strings:
    $key_b6a7 = { e5 c8 [2] c1 c6 [2] ea ea [2] c4 c8 [2] d0 d3 [2] df c9 [2] c1 d4 [2] c3 d5 [2] d8 d3 [2] c4 d4 [2] d8 fb }

  condition:
    any of them
}