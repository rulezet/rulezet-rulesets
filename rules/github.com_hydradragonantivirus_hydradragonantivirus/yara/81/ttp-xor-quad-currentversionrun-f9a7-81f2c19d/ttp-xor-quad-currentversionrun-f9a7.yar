rule TTP_XOR_QUAD_CurrentVersionRun_f9a7 {
  strings:
    $key_f9a7 = { aa c8 [2] 8e c6 [2] a5 ea [2] 8b c8 [2] 9f d3 [2] 90 c9 [2] 8e d4 [2] 8c d5 [2] 97 d3 [2] 8b d4 [2] 97 fb }

  condition:
    any of them
}