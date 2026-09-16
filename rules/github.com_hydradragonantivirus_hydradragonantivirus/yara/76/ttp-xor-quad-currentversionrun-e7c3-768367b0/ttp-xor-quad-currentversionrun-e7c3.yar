rule TTP_XOR_QUAD_CurrentVersionRun_e7c3 {
  strings:
    $key_e7c3 = { b4 ac [2] 90 a2 [2] bb 8e [2] 95 ac [2] 81 b7 [2] 8e ad [2] 90 b0 [2] 92 b1 [2] 89 b7 [2] 95 b0 [2] 89 9f }

  condition:
    any of them
}