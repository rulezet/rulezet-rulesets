rule TTP_XOR_QUAD_CurrentVersionRun_06a7 {
  strings:
    $key_06a7 = { 55 c8 [2] 71 c6 [2] 5a ea [2] 74 c8 [2] 60 d3 [2] 6f c9 [2] 71 d4 [2] 73 d5 [2] 68 d3 [2] 74 d4 [2] 68 fb }

  condition:
    any of them
}