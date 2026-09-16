rule TTP_XOR_QUAD_CurrentVersionRun_17a7 {
  strings:
    $key_17a7 = { 44 c8 [2] 60 c6 [2] 4b ea [2] 65 c8 [2] 71 d3 [2] 7e c9 [2] 60 d4 [2] 62 d5 [2] 79 d3 [2] 65 d4 [2] 79 fb }

  condition:
    any of them
}