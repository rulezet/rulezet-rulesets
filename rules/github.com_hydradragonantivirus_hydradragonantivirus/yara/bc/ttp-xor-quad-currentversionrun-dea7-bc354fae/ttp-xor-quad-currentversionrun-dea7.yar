rule TTP_XOR_QUAD_CurrentVersionRun_dea7 {
  strings:
    $key_dea7 = { 8d c8 [2] a9 c6 [2] 82 ea [2] ac c8 [2] b8 d3 [2] b7 c9 [2] a9 d4 [2] ab d5 [2] b0 d3 [2] ac d4 [2] b0 fb }

  condition:
    any of them
}