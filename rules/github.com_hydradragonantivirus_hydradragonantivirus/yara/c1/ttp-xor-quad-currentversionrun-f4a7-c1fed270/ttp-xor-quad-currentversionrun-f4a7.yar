rule TTP_XOR_QUAD_CurrentVersionRun_f4a7 {
  strings:
    $key_f4a7 = { a7 c8 [2] 83 c6 [2] a8 ea [2] 86 c8 [2] 92 d3 [2] 9d c9 [2] 83 d4 [2] 81 d5 [2] 9a d3 [2] 86 d4 [2] 9a fb }

  condition:
    any of them
}