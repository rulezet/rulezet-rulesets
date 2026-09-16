rule TTP_XOR_QUAD_CurrentVersionRun_11a7 {
  strings:
    $key_11a7 = { 42 c8 [2] 66 c6 [2] 4d ea [2] 63 c8 [2] 77 d3 [2] 78 c9 [2] 66 d4 [2] 64 d5 [2] 7f d3 [2] 63 d4 [2] 7f fb }

  condition:
    any of them
}