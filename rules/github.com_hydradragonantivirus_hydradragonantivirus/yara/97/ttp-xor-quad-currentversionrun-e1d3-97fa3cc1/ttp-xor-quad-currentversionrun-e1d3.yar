rule TTP_XOR_QUAD_CurrentVersionRun_e1d3 {
  strings:
    $key_e1d3 = { b2 bc [2] 96 b2 [2] bd 9e [2] 93 bc [2] 87 a7 [2] 88 bd [2] 96 a0 [2] 94 a1 [2] 8f a7 [2] 93 a0 [2] 8f 8f }

  condition:
    any of them
}