rule TTP_XOR_QUAD_CurrentVersionRun_99b4 {
  strings:
    $key_99b4 = { ca db [2] ee d5 [2] c5 f9 [2] eb db [2] ff c0 [2] f0 da [2] ee c7 [2] ec c6 [2] f7 c0 [2] eb c7 [2] f7 e8 }

  condition:
    any of them
}