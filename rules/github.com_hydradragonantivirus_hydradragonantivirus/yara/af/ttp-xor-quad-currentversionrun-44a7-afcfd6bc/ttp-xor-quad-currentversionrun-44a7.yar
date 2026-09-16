rule TTP_XOR_QUAD_CurrentVersionRun_44a7 {
  strings:
    $key_44a7 = { 17 c8 [2] 33 c6 [2] 18 ea [2] 36 c8 [2] 22 d3 [2] 2d c9 [2] 33 d4 [2] 31 d5 [2] 2a d3 [2] 36 d4 [2] 2a fb }

  condition:
    any of them
}