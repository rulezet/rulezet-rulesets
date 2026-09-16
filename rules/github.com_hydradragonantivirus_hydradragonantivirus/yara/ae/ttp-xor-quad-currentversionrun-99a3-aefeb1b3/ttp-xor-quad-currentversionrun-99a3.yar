rule TTP_XOR_QUAD_CurrentVersionRun_99a3 {
  strings:
    $key_99a3 = { ca cc [2] ee c2 [2] c5 ee [2] eb cc [2] ff d7 [2] f0 cd [2] ee d0 [2] ec d1 [2] f7 d7 [2] eb d0 [2] f7 ff }

  condition:
    any of them
}