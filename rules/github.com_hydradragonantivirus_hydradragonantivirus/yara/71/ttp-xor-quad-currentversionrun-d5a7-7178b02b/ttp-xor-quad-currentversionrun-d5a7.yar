rule TTP_XOR_QUAD_CurrentVersionRun_d5a7 {
  strings:
    $key_d5a7 = { 86 c8 [2] a2 c6 [2] 89 ea [2] a7 c8 [2] b3 d3 [2] bc c9 [2] a2 d4 [2] a0 d5 [2] bb d3 [2] a7 d4 [2] bb fb }

  condition:
    any of them
}