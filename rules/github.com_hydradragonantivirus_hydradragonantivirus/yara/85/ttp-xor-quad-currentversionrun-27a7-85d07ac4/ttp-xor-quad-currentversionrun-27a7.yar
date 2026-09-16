rule TTP_XOR_QUAD_CurrentVersionRun_27a7 {
  strings:
    $key_27a7 = { 74 c8 [2] 50 c6 [2] 7b ea [2] 55 c8 [2] 41 d3 [2] 4e c9 [2] 50 d4 [2] 52 d5 [2] 49 d3 [2] 55 d4 [2] 49 fb }

  condition:
    any of them
}