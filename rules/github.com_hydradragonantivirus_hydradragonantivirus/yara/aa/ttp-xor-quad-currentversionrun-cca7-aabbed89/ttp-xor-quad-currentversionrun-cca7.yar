rule TTP_XOR_QUAD_CurrentVersionRun_cca7 {
  strings:
    $key_cca7 = { 9f c8 [2] bb c6 [2] 90 ea [2] be c8 [2] aa d3 [2] a5 c9 [2] bb d4 [2] b9 d5 [2] a2 d3 [2] be d4 [2] a2 fb }

  condition:
    any of them
}