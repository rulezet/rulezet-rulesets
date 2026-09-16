rule TTP_XOR_QUAD_CurrentVersionRun_19a7 {
  strings:
    $key_19a7 = { 4a c8 [2] 6e c6 [2] 45 ea [2] 6b c8 [2] 7f d3 [2] 70 c9 [2] 6e d4 [2] 6c d5 [2] 77 d3 [2] 6b d4 [2] 77 fb }

  condition:
    any of them
}