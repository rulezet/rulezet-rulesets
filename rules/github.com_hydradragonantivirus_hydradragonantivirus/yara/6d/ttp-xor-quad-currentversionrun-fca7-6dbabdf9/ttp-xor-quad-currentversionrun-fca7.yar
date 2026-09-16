rule TTP_XOR_QUAD_CurrentVersionRun_fca7 {
  strings:
    $key_fca7 = { af c8 [2] 8b c6 [2] a0 ea [2] 8e c8 [2] 9a d3 [2] 95 c9 [2] 8b d4 [2] 89 d5 [2] 92 d3 [2] 8e d4 [2] 92 fb }

  condition:
    any of them
}