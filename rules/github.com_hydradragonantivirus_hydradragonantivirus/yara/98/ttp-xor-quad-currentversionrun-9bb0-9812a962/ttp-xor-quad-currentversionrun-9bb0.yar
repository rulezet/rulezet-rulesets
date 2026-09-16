rule TTP_XOR_QUAD_CurrentVersionRun_9bb0 {
  strings:
    $key_9bb0 = { c8 df [2] ec d1 [2] c7 fd [2] e9 df [2] fd c4 [2] f2 de [2] ec c3 [2] ee c2 [2] f5 c4 [2] e9 c3 [2] f5 ec }

  condition:
    any of them
}