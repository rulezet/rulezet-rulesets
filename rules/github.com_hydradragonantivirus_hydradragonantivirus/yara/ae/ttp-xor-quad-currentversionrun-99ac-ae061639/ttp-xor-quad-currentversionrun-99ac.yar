rule TTP_XOR_QUAD_CurrentVersionRun_99ac {
  strings:
    $key_99ac = { ca c3 [2] ee cd [2] c5 e1 [2] eb c3 [2] ff d8 [2] f0 c2 [2] ee df [2] ec de [2] f7 d8 [2] eb df [2] f7 f0 }

  condition:
    any of them
}