rule TTP_XOR_QUAD_CurrentVersionRun_9e9c {
  strings:
    $key_9e9c = { cd f3 [2] e9 fd [2] c2 d1 [2] ec f3 [2] f8 e8 [2] f7 f2 [2] e9 ef [2] eb ee [2] f0 e8 [2] ec ef [2] f0 c0 }

  condition:
    any of them
}