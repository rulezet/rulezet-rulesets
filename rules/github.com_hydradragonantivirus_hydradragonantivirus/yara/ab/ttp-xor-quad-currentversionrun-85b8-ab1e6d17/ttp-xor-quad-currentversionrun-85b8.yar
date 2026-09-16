rule TTP_XOR_QUAD_CurrentVersionRun_85b8 {
  strings:
    $key_85b8 = { d6 d7 [2] f2 d9 [2] d9 f5 [2] f7 d7 [2] e3 cc [2] ec d6 [2] f2 cb [2] f0 ca [2] eb cc [2] f7 cb [2] eb e4 }

  condition:
    any of them
}