rule TTP_XOR_QUAD_CurrentVersionRun_f3c3 {
  strings:
    $key_f3c3 = { a0 ac [2] 84 a2 [2] af 8e [2] 81 ac [2] 95 b7 [2] 9a ad [2] 84 b0 [2] 86 b1 [2] 9d b7 [2] 81 b0 [2] 9d 9f }

  condition:
    any of them
}