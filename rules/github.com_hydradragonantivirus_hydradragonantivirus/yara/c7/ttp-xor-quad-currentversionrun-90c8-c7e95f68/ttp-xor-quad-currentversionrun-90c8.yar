rule TTP_XOR_QUAD_CurrentVersionRun_90c8 {
  strings:
    $key_90c8 = { c3 a7 [2] e7 a9 [2] cc 85 [2] e2 a7 [2] f6 bc [2] f9 a6 [2] e7 bb [2] e5 ba [2] fe bc [2] e2 bb [2] fe 94 }

  condition:
    any of them
}