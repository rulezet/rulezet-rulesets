rule TTP_XOR_QUAD_CurrentVersionRun_3fa7 {
  strings:
    $key_3fa7 = { 6c c8 [2] 48 c6 [2] 63 ea [2] 4d c8 [2] 59 d3 [2] 56 c9 [2] 48 d4 [2] 4a d5 [2] 51 d3 [2] 4d d4 [2] 51 fb }

  condition:
    any of them
}