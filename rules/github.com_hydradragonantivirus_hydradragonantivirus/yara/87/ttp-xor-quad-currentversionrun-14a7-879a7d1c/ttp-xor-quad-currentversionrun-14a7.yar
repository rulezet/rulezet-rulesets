rule TTP_XOR_QUAD_CurrentVersionRun_14a7 {
  strings:
    $key_14a7 = { 47 c8 [2] 63 c6 [2] 48 ea [2] 66 c8 [2] 72 d3 [2] 7d c9 [2] 63 d4 [2] 61 d5 [2] 7a d3 [2] 66 d4 [2] 7a fb }

  condition:
    any of them
}