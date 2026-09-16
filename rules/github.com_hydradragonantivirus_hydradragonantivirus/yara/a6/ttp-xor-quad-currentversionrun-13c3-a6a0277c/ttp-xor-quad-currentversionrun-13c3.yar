rule TTP_XOR_QUAD_CurrentVersionRun_13c3 {
  strings:
    $key_13c3 = { 40 ac [2] 64 a2 [2] 4f 8e [2] 61 ac [2] 75 b7 [2] 7a ad [2] 64 b0 [2] 66 b1 [2] 7d b7 [2] 61 b0 [2] 7d 9f }

  condition:
    any of them
}