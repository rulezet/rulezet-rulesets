rule TTP_XOR_QUAD_CurrentVersionRun_67a7 {
  strings:
    $key_67a7 = { 34 c8 [2] 10 c6 [2] 3b ea [2] 15 c8 [2] 01 d3 [2] 0e c9 [2] 10 d4 [2] 12 d5 [2] 09 d3 [2] 15 d4 [2] 09 fb }

  condition:
    any of them
}