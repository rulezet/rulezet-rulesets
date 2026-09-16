rule TTP_XOR_QUAD_CurrentVersionRun_82be {
  strings:
    $key_82be = { d1 d1 [2] f5 df [2] de f3 [2] f0 d1 [2] e4 ca [2] eb d0 [2] f5 cd [2] f7 cc [2] ec ca [2] f0 cd [2] ec e2 }

  condition:
    any of them
}