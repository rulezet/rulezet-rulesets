rule TTP_XOR_QUAD_CurrentVersionRun_22a7 {
  strings:
    $key_22a7 = { 71 c8 [2] 55 c6 [2] 7e ea [2] 50 c8 [2] 44 d3 [2] 4b c9 [2] 55 d4 [2] 57 d5 [2] 4c d3 [2] 50 d4 [2] 4c fb }

  condition:
    any of them
}