rule TTP_XOR_QUAD_CurrentVersionRun_f5a7 {
  strings:
    $key_f5a7 = { a6 c8 [2] 82 c6 [2] a9 ea [2] 87 c8 [2] 93 d3 [2] 9c c9 [2] 82 d4 [2] 80 d5 [2] 9b d3 [2] 87 d4 [2] 9b fb }

  condition:
    any of them
}