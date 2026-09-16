rule TTP_XOR_QUAD_CurrentVersionRun_82b8 {
  strings:
    $key_82b8 = { d1 d7 [2] f5 d9 [2] de f5 [2] f0 d7 [2] e4 cc [2] eb d6 [2] f5 cb [2] f7 ca [2] ec cc [2] f0 cb [2] ec e4 }

  condition:
    any of them
}