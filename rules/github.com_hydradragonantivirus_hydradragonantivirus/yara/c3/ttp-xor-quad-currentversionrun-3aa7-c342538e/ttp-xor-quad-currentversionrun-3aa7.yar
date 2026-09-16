rule TTP_XOR_QUAD_CurrentVersionRun_3aa7 {
  strings:
    $key_3aa7 = { 69 c8 [2] 4d c6 [2] 66 ea [2] 48 c8 [2] 5c d3 [2] 53 c9 [2] 4d d4 [2] 4f d5 [2] 54 d3 [2] 48 d4 [2] 54 fb }

  condition:
    any of them
}