rule TTP_XOR_QUAD_CurrentVersionRun_29a7 {
  strings:
    $key_29a7 = { 7a c8 [2] 5e c6 [2] 75 ea [2] 5b c8 [2] 4f d3 [2] 40 c9 [2] 5e d4 [2] 5c d5 [2] 47 d3 [2] 5b d4 [2] 47 fb }

  condition:
    any of them
}