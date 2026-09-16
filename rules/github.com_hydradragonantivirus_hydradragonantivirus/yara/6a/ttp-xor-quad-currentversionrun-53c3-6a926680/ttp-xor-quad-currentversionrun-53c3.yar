rule TTP_XOR_QUAD_CurrentVersionRun_53c3 {
  strings:
    $key_53c3 = { 00 ac [2] 24 a2 [2] 0f 8e [2] 21 ac [2] 35 b7 [2] 3a ad [2] 24 b0 [2] 26 b1 [2] 3d b7 [2] 21 b0 [2] 3d 9f }

  condition:
    any of them
}