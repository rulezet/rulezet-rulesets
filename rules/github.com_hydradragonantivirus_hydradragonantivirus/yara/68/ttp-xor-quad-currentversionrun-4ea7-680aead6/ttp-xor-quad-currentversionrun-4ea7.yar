rule TTP_XOR_QUAD_CurrentVersionRun_4ea7 {
  strings:
    $key_4ea7 = { 1d c8 [2] 39 c6 [2] 12 ea [2] 3c c8 [2] 28 d3 [2] 27 c9 [2] 39 d4 [2] 3b d5 [2] 20 d3 [2] 3c d4 [2] 20 fb }

  condition:
    any of them
}