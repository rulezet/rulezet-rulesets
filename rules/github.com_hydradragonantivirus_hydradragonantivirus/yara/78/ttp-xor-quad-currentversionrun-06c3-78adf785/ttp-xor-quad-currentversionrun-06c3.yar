rule TTP_XOR_QUAD_CurrentVersionRun_06c3 {
  strings:
    $key_06c3 = { 55 ac [2] 71 a2 [2] 5a 8e [2] 74 ac [2] 60 b7 [2] 6f ad [2] 71 b0 [2] 73 b1 [2] 68 b7 [2] 74 b0 [2] 68 9f }

  condition:
    any of them
}