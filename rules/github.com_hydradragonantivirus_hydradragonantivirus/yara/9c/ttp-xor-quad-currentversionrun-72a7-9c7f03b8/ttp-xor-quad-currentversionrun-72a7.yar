rule TTP_XOR_QUAD_CurrentVersionRun_72a7 {
  strings:
    $key_72a7 = { 21 c8 [2] 05 c6 [2] 2e ea [2] 00 c8 [2] 14 d3 [2] 1b c9 [2] 05 d4 [2] 07 d5 [2] 1c d3 [2] 00 d4 [2] 1c fb }

  condition:
    any of them
}