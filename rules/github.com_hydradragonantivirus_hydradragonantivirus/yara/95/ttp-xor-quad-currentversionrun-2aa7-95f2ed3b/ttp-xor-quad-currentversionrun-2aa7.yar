rule TTP_XOR_QUAD_CurrentVersionRun_2aa7 {
  strings:
    $key_2aa7 = { 79 c8 [2] 5d c6 [2] 76 ea [2] 58 c8 [2] 4c d3 [2] 43 c9 [2] 5d d4 [2] 5f d5 [2] 44 d3 [2] 58 d4 [2] 44 fb }

  condition:
    any of them
}