rule TTP_XOR_QUAD_CurrentVersionRun_47c3 {
  strings:
    $key_47c3 = { 14 ac [2] 30 a2 [2] 1b 8e [2] 35 ac [2] 21 b7 [2] 2e ad [2] 30 b0 [2] 32 b1 [2] 29 b7 [2] 35 b0 [2] 29 9f }

  condition:
    any of them
}