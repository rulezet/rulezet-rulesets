rule TTP_XOR_QUAD_CurrentVersionRun_a2c3 {
  strings:
    $key_a2c3 = { f1 ac [2] d5 a2 [2] fe 8e [2] d0 ac [2] c4 b7 [2] cb ad [2] d5 b0 [2] d7 b1 [2] cc b7 [2] d0 b0 [2] cc 9f }

  condition:
    any of them
}