rule TTP_XOR_QUAD_CurrentVersionRun_08a7 {
  strings:
    $key_08a7 = { 5b c8 [2] 7f c6 [2] 54 ea [2] 7a c8 [2] 6e d3 [2] 61 c9 [2] 7f d4 [2] 7d d5 [2] 66 d3 [2] 7a d4 [2] 66 fb }

  condition:
    any of them
}