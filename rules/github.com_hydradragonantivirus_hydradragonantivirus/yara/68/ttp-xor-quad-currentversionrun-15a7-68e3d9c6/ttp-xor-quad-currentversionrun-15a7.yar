rule TTP_XOR_QUAD_CurrentVersionRun_15a7 {
  strings:
    $key_15a7 = { 46 c8 [2] 62 c6 [2] 49 ea [2] 67 c8 [2] 73 d3 [2] 7c c9 [2] 62 d4 [2] 60 d5 [2] 7b d3 [2] 67 d4 [2] 7b fb }

  condition:
    any of them
}