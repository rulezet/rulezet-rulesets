rule TTP_XOR_QUAD_CurrentVersionRun_9ca9 {
  strings:
    $key_9ca9 = { cf c6 [2] eb c8 [2] c0 e4 [2] ee c6 [2] fa dd [2] f5 c7 [2] eb da [2] e9 db [2] f2 dd [2] ee da [2] f2 f5 }

  condition:
    any of them
}