rule TTP_XOR_QUAD_CurrentVersionRun_85b0 {
  strings:
    $key_85b0 = { d6 df [2] f2 d1 [2] d9 fd [2] f7 df [2] e3 c4 [2] ec de [2] f2 c3 [2] f0 c2 [2] eb c4 [2] f7 c3 [2] eb ec }

  condition:
    any of them
}