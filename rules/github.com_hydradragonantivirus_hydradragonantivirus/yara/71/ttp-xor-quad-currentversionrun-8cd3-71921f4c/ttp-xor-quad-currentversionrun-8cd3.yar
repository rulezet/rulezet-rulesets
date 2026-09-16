rule TTP_XOR_QUAD_CurrentVersionRun_8cd3 {
  strings:
    $key_8cd3 = { df bc [2] fb b2 [2] d0 9e [2] fe bc [2] ea a7 [2] e5 bd [2] fb a0 [2] f9 a1 [2] e2 a7 [2] fe a0 [2] e2 8f }

  condition:
    any of them
}