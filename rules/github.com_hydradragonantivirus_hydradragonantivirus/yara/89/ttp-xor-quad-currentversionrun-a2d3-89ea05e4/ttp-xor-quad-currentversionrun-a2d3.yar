rule TTP_XOR_QUAD_CurrentVersionRun_a2d3 {
  strings:
    $key_a2d3 = { f1 bc [2] d5 b2 [2] fe 9e [2] d0 bc [2] c4 a7 [2] cb bd [2] d5 a0 [2] d7 a1 [2] cc a7 [2] d0 a0 [2] cc 8f }

  condition:
    any of them
}