rule TTP_XOR_QUAD_CurrentVersionRun_12a7 {
  strings:
    $key_12a7 = { 41 c8 [2] 65 c6 [2] 4e ea [2] 60 c8 [2] 74 d3 [2] 7b c9 [2] 65 d4 [2] 67 d5 [2] 7c d3 [2] 60 d4 [2] 7c fb }

  condition:
    any of them
}