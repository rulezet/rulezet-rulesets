rule TTP_XOR_QUAD_CurrentVersionRun_99a9 {
  strings:
    $key_99a9 = { ca c6 [2] ee c8 [2] c5 e4 [2] eb c6 [2] ff dd [2] f0 c7 [2] ee da [2] ec db [2] f7 dd [2] eb da [2] f7 f5 }

  condition:
    any of them
}