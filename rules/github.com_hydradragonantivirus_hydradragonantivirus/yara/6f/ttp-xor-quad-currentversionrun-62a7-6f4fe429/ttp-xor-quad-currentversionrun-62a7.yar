rule TTP_XOR_QUAD_CurrentVersionRun_62a7 {
  strings:
    $key_62a7 = { 31 c8 [2] 15 c6 [2] 3e ea [2] 10 c8 [2] 04 d3 [2] 0b c9 [2] 15 d4 [2] 17 d5 [2] 0c d3 [2] 10 d4 [2] 0c fb }

  condition:
    any of them
}