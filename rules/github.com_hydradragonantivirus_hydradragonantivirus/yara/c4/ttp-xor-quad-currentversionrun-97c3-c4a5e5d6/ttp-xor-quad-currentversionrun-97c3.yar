rule TTP_XOR_QUAD_CurrentVersionRun_97c3 {
  strings:
    $key_97c3 = { c4 ac [2] e0 a2 [2] cb 8e [2] e5 ac [2] f1 b7 [2] fe ad [2] e0 b0 [2] e2 b1 [2] f9 b7 [2] e5 b0 [2] f9 9f }

  condition:
    any of them
}