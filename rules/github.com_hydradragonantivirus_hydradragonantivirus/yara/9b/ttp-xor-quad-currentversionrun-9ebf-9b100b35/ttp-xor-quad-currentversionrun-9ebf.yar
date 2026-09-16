rule TTP_XOR_QUAD_CurrentVersionRun_9ebf {
  strings:
    $key_9ebf = { cd d0 [2] e9 de [2] c2 f2 [2] ec d0 [2] f8 cb [2] f7 d1 [2] e9 cc [2] eb cd [2] f0 cb [2] ec cc [2] f0 e3 }

  condition:
    any of them
}