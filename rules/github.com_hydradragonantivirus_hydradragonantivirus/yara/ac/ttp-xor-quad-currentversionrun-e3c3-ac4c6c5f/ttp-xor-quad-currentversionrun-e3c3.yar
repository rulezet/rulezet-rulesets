rule TTP_XOR_QUAD_CurrentVersionRun_e3c3 {
  strings:
    $key_e3c3 = { b0 ac [2] 94 a2 [2] bf 8e [2] 91 ac [2] 85 b7 [2] 8a ad [2] 94 b0 [2] 96 b1 [2] 8d b7 [2] 91 b0 [2] 8d 9f }

  condition:
    any of them
}