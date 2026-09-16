rule TTP_XOR_QUAD_CurrentVersionRun_e2a7 {
  strings:
    $key_e2a7 = { b1 c8 [2] 95 c6 [2] be ea [2] 90 c8 [2] 84 d3 [2] 8b c9 [2] 95 d4 [2] 97 d5 [2] 8c d3 [2] 90 d4 [2] 8c fb }

  condition:
    any of them
}