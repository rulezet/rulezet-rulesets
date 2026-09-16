rule TTP_XOR_QUAD_CurrentVersionRun_1fa7 {
  strings:
    $key_1fa7 = { 4c c8 [2] 68 c6 [2] 43 ea [2] 6d c8 [2] 79 d3 [2] 76 c9 [2] 68 d4 [2] 6a d5 [2] 71 d3 [2] 6d d4 [2] 71 fb }

  condition:
    any of them
}