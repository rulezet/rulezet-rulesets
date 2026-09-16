rule TTP_XOR_QUAD_CurrentVersionRun_48a7 {
  strings:
    $key_48a7 = { 1b c8 [2] 3f c6 [2] 14 ea [2] 3a c8 [2] 2e d3 [2] 21 c9 [2] 3f d4 [2] 3d d5 [2] 26 d3 [2] 3a d4 [2] 26 fb }

  condition:
    any of them
}