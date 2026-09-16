rule TTP_XOR_QUAD_CurrentVersionRun_90a7 {
  strings:
    $key_90a7 = { c3 c8 [2] e7 c6 [2] cc ea [2] e2 c8 [2] f6 d3 [2] f9 c9 [2] e7 d4 [2] e5 d5 [2] fe d3 [2] e2 d4 [2] fe fb }

  condition:
    any of them
}