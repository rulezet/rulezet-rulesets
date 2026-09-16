rule TTP_XOR_QUAD_CurrentVersionRun_6da7 {
  strings:
    $key_6da7 = { 3e c8 [2] 1a c6 [2] 31 ea [2] 1f c8 [2] 0b d3 [2] 04 c9 [2] 1a d4 [2] 18 d5 [2] 03 d3 [2] 1f d4 [2] 03 fb }

  condition:
    any of them
}