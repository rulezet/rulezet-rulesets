rule TTP_XOR_QUAD_CurrentVersionRun_30a7 {
  strings:
    $key_30a7 = { 63 c8 [2] 47 c6 [2] 6c ea [2] 42 c8 [2] 56 d3 [2] 59 c9 [2] 47 d4 [2] 45 d5 [2] 5e d3 [2] 42 d4 [2] 5e fb }

  condition:
    any of them
}