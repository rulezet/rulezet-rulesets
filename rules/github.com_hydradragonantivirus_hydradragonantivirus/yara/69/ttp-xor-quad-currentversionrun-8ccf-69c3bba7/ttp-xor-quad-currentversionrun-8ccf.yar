rule TTP_XOR_QUAD_CurrentVersionRun_8ccf {
  strings:
    $key_8ccf = { df a0 [2] fb ae [2] d0 82 [2] fe a0 [2] ea bb [2] e5 a1 [2] fb bc [2] f9 bd [2] e2 bb [2] fe bc [2] e2 93 }

  condition:
    any of them
}