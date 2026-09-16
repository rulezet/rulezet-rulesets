rule TTP_XOR_QUAD_CurrentVersionRun_c5a7 {
  strings:
    $key_c5a7 = { 96 c8 [2] b2 c6 [2] 99 ea [2] b7 c8 [2] a3 d3 [2] ac c9 [2] b2 d4 [2] b0 d5 [2] ab d3 [2] b7 d4 [2] ab fb }

  condition:
    any of them
}