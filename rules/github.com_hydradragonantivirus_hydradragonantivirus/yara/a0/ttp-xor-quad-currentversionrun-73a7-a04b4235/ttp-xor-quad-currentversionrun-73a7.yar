rule TTP_XOR_QUAD_CurrentVersionRun_73a7 {
  strings:
    $key_73a7 = { 20 c8 [2] 04 c6 [2] 2f ea [2] 01 c8 [2] 15 d3 [2] 1a c9 [2] 04 d4 [2] 06 d5 [2] 1d d3 [2] 01 d4 [2] 1d fb }

  condition:
    any of them
}