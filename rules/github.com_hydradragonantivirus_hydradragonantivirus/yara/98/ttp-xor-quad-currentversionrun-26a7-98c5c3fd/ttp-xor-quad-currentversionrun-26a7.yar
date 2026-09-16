rule TTP_XOR_QUAD_CurrentVersionRun_26a7 {
  strings:
    $key_26a7 = { 75 c8 [2] 51 c6 [2] 7a ea [2] 54 c8 [2] 40 d3 [2] 4f c9 [2] 51 d4 [2] 53 d5 [2] 48 d3 [2] 54 d4 [2] 48 fb }

  condition:
    any of them
}