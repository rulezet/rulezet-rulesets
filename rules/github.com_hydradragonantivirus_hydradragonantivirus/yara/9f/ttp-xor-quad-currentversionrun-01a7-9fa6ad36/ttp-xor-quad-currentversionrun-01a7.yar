rule TTP_XOR_QUAD_CurrentVersionRun_01a7 {
  strings:
    $key_01a7 = { 52 c8 [2] 76 c6 [2] 5d ea [2] 73 c8 [2] 67 d3 [2] 68 c9 [2] 76 d4 [2] 74 d5 [2] 6f d3 [2] 73 d4 [2] 6f fb }

  condition:
    any of them
}