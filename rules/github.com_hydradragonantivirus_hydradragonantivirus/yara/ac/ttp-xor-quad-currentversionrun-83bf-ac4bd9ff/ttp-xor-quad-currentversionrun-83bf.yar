rule TTP_XOR_QUAD_CurrentVersionRun_83bf {
  strings:
    $key_83bf = { d0 d0 [2] f4 de [2] df f2 [2] f1 d0 [2] e5 cb [2] ea d1 [2] f4 cc [2] f6 cd [2] ed cb [2] f1 cc [2] ed e3 }

  condition:
    any of them
}