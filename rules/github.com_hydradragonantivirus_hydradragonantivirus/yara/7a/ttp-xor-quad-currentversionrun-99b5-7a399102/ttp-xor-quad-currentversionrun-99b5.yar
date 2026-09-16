rule TTP_XOR_QUAD_CurrentVersionRun_99b5 {
  strings:
    $key_99b5 = { ca da [2] ee d4 [2] c5 f8 [2] eb da [2] ff c1 [2] f0 db [2] ee c6 [2] ec c7 [2] f7 c1 [2] eb c6 [2] f7 e9 }

  condition:
    any of them
}