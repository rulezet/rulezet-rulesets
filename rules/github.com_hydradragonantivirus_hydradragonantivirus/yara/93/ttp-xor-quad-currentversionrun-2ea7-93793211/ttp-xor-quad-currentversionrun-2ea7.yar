rule TTP_XOR_QUAD_CurrentVersionRun_2ea7 {
  strings:
    $key_2ea7 = { 7d c8 [2] 59 c6 [2] 72 ea [2] 5c c8 [2] 48 d3 [2] 47 c9 [2] 59 d4 [2] 5b d5 [2] 40 d3 [2] 5c d4 [2] 40 fb }

  condition:
    any of them
}