rule TTP_XOR_QUAD_CurrentVersionRun_c9a7 {
  strings:
    $key_c9a7 = { 9a c8 [2] be c6 [2] 95 ea [2] bb c8 [2] af d3 [2] a0 c9 [2] be d4 [2] bc d5 [2] a7 d3 [2] bb d4 [2] a7 fb }

  condition:
    any of them
}