rule TTP_XOR_QUAD_CurrentVersionRun_87ab {
  strings:
    $key_87ab = { d4 c4 [2] f0 ca [2] db e6 [2] f5 c4 [2] e1 df [2] ee c5 [2] f0 d8 [2] f2 d9 [2] e9 df [2] f5 d8 [2] e9 f7 }

  condition:
    any of them
}