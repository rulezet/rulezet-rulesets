rule TTP_XOR_QUAD_CurrentVersionRun_4ba7 {
  strings:
    $key_4ba7 = { 18 c8 [2] 3c c6 [2] 17 ea [2] 39 c8 [2] 2d d3 [2] 22 c9 [2] 3c d4 [2] 3e d5 [2] 25 d3 [2] 39 d4 [2] 25 fb }

  condition:
    any of them
}