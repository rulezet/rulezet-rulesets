rule TTP_XOR_QUAD_CurrentVersionRun_7fa7 {
  strings:
    $key_7fa7 = { 2c c8 [2] 08 c6 [2] 23 ea [2] 0d c8 [2] 19 d3 [2] 16 c9 [2] 08 d4 [2] 0a d5 [2] 11 d3 [2] 0d d4 [2] 11 fb }

  condition:
    any of them
}