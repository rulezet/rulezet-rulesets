rule TTP_XOR_QUAD_CurrentVersionRun_f0c3 {
  strings:
    $key_f0c3 = { a3 ac [2] 87 a2 [2] ac 8e [2] 82 ac [2] 96 b7 [2] 99 ad [2] 87 b0 [2] 85 b1 [2] 9e b7 [2] 82 b0 [2] 9e 9f }

  condition:
    any of them
}