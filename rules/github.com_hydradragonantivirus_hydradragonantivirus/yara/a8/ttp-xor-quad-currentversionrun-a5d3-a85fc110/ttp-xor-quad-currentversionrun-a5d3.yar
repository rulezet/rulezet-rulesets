rule TTP_XOR_QUAD_CurrentVersionRun_a5d3 {
  strings:
    $key_a5d3 = { f6 bc [2] d2 b2 [2] f9 9e [2] d7 bc [2] c3 a7 [2] cc bd [2] d2 a0 [2] d0 a1 [2] cb a7 [2] d7 a0 [2] cb 8f }

  condition:
    any of them
}