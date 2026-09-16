rule TTP_XOR_QUAD_CurrentVersionRun_a0a7 {
  strings:
    $key_a0a7 = { f3 c8 [2] d7 c6 [2] fc ea [2] d2 c8 [2] c6 d3 [2] c9 c9 [2] d7 d4 [2] d5 d5 [2] ce d3 [2] d2 d4 [2] ce fb }

  condition:
    any of them
}