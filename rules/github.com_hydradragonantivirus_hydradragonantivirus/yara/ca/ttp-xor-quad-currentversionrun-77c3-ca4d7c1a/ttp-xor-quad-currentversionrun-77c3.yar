rule TTP_XOR_QUAD_CurrentVersionRun_77c3 {
  strings:
    $key_77c3 = { 24 ac [2] 00 a2 [2] 2b 8e [2] 05 ac [2] 11 b7 [2] 1e ad [2] 00 b0 [2] 02 b1 [2] 19 b7 [2] 05 b0 [2] 19 9f }

  condition:
    any of them
}