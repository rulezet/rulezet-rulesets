rule TTP_XOR_QUAD_CurrentVersionRun_0fa7 {
  strings:
    $key_0fa7 = { 5c c8 [2] 78 c6 [2] 53 ea [2] 7d c8 [2] 69 d3 [2] 66 c9 [2] 78 d4 [2] 7a d5 [2] 61 d3 [2] 7d d4 [2] 61 fb }

  condition:
    any of them
}