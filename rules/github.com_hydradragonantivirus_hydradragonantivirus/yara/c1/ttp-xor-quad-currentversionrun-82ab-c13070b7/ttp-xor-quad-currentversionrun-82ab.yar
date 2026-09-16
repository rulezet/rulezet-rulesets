rule TTP_XOR_QUAD_CurrentVersionRun_82ab {
  strings:
    $key_82ab = { d1 c4 [2] f5 ca [2] de e6 [2] f0 c4 [2] e4 df [2] eb c5 [2] f5 d8 [2] f7 d9 [2] ec df [2] f0 d8 [2] ec f7 }

  condition:
    any of them
}