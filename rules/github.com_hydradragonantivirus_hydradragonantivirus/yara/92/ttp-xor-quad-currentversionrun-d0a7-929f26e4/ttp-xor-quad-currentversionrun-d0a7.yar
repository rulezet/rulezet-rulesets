rule TTP_XOR_QUAD_CurrentVersionRun_d0a7 {
  strings:
    $key_d0a7 = { 83 c8 [2] a7 c6 [2] 8c ea [2] a2 c8 [2] b6 d3 [2] b9 c9 [2] a7 d4 [2] a5 d5 [2] be d3 [2] a2 d4 [2] be fb }

  condition:
    any of them
}