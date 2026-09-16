rule TTP_XOR_QUAD_CurrentVersionRun_76a7 {
  strings:
    $key_76a7 = { 25 c8 [2] 01 c6 [2] 2a ea [2] 04 c8 [2] 10 d3 [2] 1f c9 [2] 01 d4 [2] 03 d5 [2] 18 d3 [2] 04 d4 [2] 18 fb }

  condition:
    any of them
}