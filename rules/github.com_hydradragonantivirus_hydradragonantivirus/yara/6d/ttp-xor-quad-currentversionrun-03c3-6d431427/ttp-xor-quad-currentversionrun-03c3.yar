rule TTP_XOR_QUAD_CurrentVersionRun_03c3 {
  strings:
    $key_03c3 = { 50 ac [2] 74 a2 [2] 5f 8e [2] 71 ac [2] 65 b7 [2] 6a ad [2] 74 b0 [2] 76 b1 [2] 6d b7 [2] 71 b0 [2] 6d 9f }

  condition:
    any of them
}