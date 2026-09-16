rule TTP_XOR_QUAD_CurrentVersionRun_89d3 {
  strings:
    $key_89d3 = { da bc [2] fe b2 [2] d5 9e [2] fb bc [2] ef a7 [2] e0 bd [2] fe a0 [2] fc a1 [2] e7 a7 [2] fb a0 [2] e7 8f }

  condition:
    any of them
}