rule TTP_XOR_QUAD_CurrentVersionRun_ffa7 {
  strings:
    $key_ffa7 = { ac c8 [2] 88 c6 [2] a3 ea [2] 8d c8 [2] 99 d3 [2] 96 c9 [2] 88 d4 [2] 8a d5 [2] 91 d3 [2] 8d d4 [2] 91 fb }

  condition:
    any of them
}