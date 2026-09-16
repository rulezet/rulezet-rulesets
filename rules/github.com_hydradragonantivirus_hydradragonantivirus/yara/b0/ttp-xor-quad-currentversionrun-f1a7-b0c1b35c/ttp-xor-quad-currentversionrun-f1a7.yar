rule TTP_XOR_QUAD_CurrentVersionRun_f1a7 {
  strings:
    $key_f1a7 = { a2 c8 [2] 86 c6 [2] ad ea [2] 83 c8 [2] 97 d3 [2] 98 c9 [2] 86 d4 [2] 84 d5 [2] 9f d3 [2] 83 d4 [2] 9f fb }

  condition:
    any of them
}