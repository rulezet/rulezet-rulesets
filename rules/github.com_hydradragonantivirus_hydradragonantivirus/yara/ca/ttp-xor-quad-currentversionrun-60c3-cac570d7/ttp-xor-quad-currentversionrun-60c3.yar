rule TTP_XOR_QUAD_CurrentVersionRun_60c3 {
  strings:
    $key_60c3 = { 33 ac [2] 17 a2 [2] 3c 8e [2] 12 ac [2] 06 b7 [2] 09 ad [2] 17 b0 [2] 15 b1 [2] 0e b7 [2] 12 b0 [2] 0e 9f }

  condition:
    any of them
}