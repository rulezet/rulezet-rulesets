rule TTP_XOR_QUAD_CurrentVersionRun_05a7 {
  strings:
    $key_05a7 = { 56 c8 [2] 72 c6 [2] 59 ea [2] 77 c8 [2] 63 d3 [2] 6c c9 [2] 72 d4 [2] 70 d5 [2] 6b d3 [2] 77 d4 [2] 6b fb }

  condition:
    any of them
}