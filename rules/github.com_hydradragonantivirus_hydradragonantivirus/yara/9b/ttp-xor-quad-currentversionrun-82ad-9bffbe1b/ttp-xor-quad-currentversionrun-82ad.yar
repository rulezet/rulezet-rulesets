rule TTP_XOR_QUAD_CurrentVersionRun_82ad {
  strings:
    $key_82ad = { d1 c2 [2] f5 cc [2] de e0 [2] f0 c2 [2] e4 d9 [2] eb c3 [2] f5 de [2] f7 df [2] ec d9 [2] f0 de [2] ec f1 }

  condition:
    any of them
}