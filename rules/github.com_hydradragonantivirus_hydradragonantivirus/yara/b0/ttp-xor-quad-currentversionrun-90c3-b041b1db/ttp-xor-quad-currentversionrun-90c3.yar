rule TTP_XOR_QUAD_CurrentVersionRun_90c3 {
  strings:
    $key_90c3 = { c3 ac [2] e7 a2 [2] cc 8e [2] e2 ac [2] f6 b7 [2] f9 ad [2] e7 b0 [2] e5 b1 [2] fe b7 [2] e2 b0 [2] fe 9f }

  condition:
    any of them
}