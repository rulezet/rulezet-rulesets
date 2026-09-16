rule TTP_XOR_QUAD_CurrentVersionRun_3ea7 {
  strings:
    $key_3ea7 = { 6d c8 [2] 49 c6 [2] 62 ea [2] 4c c8 [2] 58 d3 [2] 57 c9 [2] 49 d4 [2] 4b d5 [2] 50 d3 [2] 4c d4 [2] 50 fb }

  condition:
    any of them
}