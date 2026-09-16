rule TTP_XOR_QUAD_CurrentVersionRun_b5d3 {
  strings:
    $key_b5d3 = { e6 bc [2] c2 b2 [2] e9 9e [2] c7 bc [2] d3 a7 [2] dc bd [2] c2 a0 [2] c0 a1 [2] db a7 [2] c7 a0 [2] db 8f }

  condition:
    any of them
}