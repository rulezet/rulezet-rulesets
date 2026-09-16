rule TTP_XOR_QUAD_CurrentVersionRun_58a7 {
  strings:
    $key_58a7 = { 0b c8 [2] 2f c6 [2] 04 ea [2] 2a c8 [2] 3e d3 [2] 31 c9 [2] 2f d4 [2] 2d d5 [2] 36 d3 [2] 2a d4 [2] 36 fb }

  condition:
    any of them
}