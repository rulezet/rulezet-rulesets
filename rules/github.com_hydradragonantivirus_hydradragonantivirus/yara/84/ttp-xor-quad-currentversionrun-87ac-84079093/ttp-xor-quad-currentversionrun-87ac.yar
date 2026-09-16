rule TTP_XOR_QUAD_CurrentVersionRun_87ac {
  strings:
    $key_87ac = { d4 c3 [2] f0 cd [2] db e1 [2] f5 c3 [2] e1 d8 [2] ee c2 [2] f0 df [2] f2 de [2] e9 d8 [2] f5 df [2] e9 f0 }

  condition:
    any of them
}