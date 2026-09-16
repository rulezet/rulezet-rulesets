rule TTP_XOR_QUAD_CurrentVersionRun_8ca9 {
  strings:
    $key_8ca9 = { df c6 [2] fb c8 [2] d0 e4 [2] fe c6 [2] ea dd [2] e5 c7 [2] fb da [2] f9 db [2] e2 dd [2] fe da [2] e2 f5 }

  condition:
    any of them
}