rule TTP_XOR_QUAD_CurrentVersionRun_99a4 {
  strings:
    $key_99a4 = { ca cb [2] ee c5 [2] c5 e9 [2] eb cb [2] ff d0 [2] f0 ca [2] ee d7 [2] ec d6 [2] f7 d0 [2] eb d7 [2] f7 f8 }

  condition:
    any of them
}