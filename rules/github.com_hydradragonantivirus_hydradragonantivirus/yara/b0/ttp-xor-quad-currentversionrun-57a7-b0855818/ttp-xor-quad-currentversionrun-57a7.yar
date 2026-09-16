rule TTP_XOR_QUAD_CurrentVersionRun_57a7 {
  strings:
    $key_57a7 = { 04 c8 [2] 20 c6 [2] 0b ea [2] 25 c8 [2] 31 d3 [2] 3e c9 [2] 20 d4 [2] 22 d5 [2] 39 d3 [2] 25 d4 [2] 39 fb }

  condition:
    any of them
}