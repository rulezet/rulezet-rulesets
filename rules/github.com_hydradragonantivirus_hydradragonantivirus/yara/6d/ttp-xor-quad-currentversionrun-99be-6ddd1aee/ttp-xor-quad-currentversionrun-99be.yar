rule TTP_XOR_QUAD_CurrentVersionRun_99be {
  strings:
    $key_99be = { ca d1 [2] ee df [2] c5 f3 [2] eb d1 [2] ff ca [2] f0 d0 [2] ee cd [2] ec cc [2] f7 ca [2] eb cd [2] f7 e2 }

  condition:
    any of them
}