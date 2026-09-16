rule TTP_XOR_QUAD_CurrentVersionRun_7aa7 {
  strings:
    $key_7aa7 = { 29 c8 [2] 0d c6 [2] 26 ea [2] 08 c8 [2] 1c d3 [2] 13 c9 [2] 0d d4 [2] 0f d5 [2] 14 d3 [2] 08 d4 [2] 14 fb }

  condition:
    any of them
}