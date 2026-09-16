rule TTP_XOR_QUAD_CurrentVersionRun_23a7 {
  strings:
    $key_23a7 = { 70 c8 [2] 54 c6 [2] 7f ea [2] 51 c8 [2] 45 d3 [2] 4a c9 [2] 54 d4 [2] 56 d5 [2] 4d d3 [2] 51 d4 [2] 4d fb }

  condition:
    any of them
}