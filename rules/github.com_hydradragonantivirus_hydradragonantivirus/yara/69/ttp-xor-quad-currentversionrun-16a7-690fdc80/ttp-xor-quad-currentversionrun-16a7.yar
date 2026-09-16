rule TTP_XOR_QUAD_CurrentVersionRun_16a7 {
  strings:
    $key_16a7 = { 45 c8 [2] 61 c6 [2] 4a ea [2] 64 c8 [2] 70 d3 [2] 7f c9 [2] 61 d4 [2] 63 d5 [2] 78 d3 [2] 64 d4 [2] 78 fb }

  condition:
    any of them
}