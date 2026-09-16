rule TTP_XOR_QUAD_CurrentVersionRun_8cb4 {
  strings:
    $key_8cb4 = { df db [2] fb d5 [2] d0 f9 [2] fe db [2] ea c0 [2] e5 da [2] fb c7 [2] f9 c6 [2] e2 c0 [2] fe c7 [2] e2 e8 }

  condition:
    any of them
}