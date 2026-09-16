rule TTP_XOR_QUAD_CurrentVersionRun_82b0 {
  strings:
    $key_82b0 = { d1 df [2] f5 d1 [2] de fd [2] f0 df [2] e4 c4 [2] eb de [2] f5 c3 [2] f7 c2 [2] ec c4 [2] f0 c3 [2] ec ec }

  condition:
    any of them
}