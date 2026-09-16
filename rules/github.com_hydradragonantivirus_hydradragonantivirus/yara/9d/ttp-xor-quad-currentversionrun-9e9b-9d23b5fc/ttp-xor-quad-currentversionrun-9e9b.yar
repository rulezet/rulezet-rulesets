rule TTP_XOR_QUAD_CurrentVersionRun_9e9b {
  strings:
    $key_9e9b = { cd f4 [2] e9 fa [2] c2 d6 [2] ec f4 [2] f8 ef [2] f7 f5 [2] e9 e8 [2] eb e9 [2] f0 ef [2] ec e8 [2] f0 c7 }

  condition:
    any of them
}