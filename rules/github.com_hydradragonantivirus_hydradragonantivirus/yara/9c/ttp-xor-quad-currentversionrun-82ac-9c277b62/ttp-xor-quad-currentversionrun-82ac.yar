rule TTP_XOR_QUAD_CurrentVersionRun_82ac {
  strings:
    $key_82ac = { d1 c3 [2] f5 cd [2] de e1 [2] f0 c3 [2] e4 d8 [2] eb c2 [2] f5 df [2] f7 de [2] ec d8 [2] f0 df [2] ec f0 }

  condition:
    any of them
}