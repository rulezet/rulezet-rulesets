rule TTP_XOR_QUAD_CurrentVersionRun_9e8e {
  strings:
    $key_9e8e = { cd e1 [2] e9 ef [2] c2 c3 [2] ec e1 [2] f8 fa [2] f7 e0 [2] e9 fd [2] eb fc [2] f0 fa [2] ec fd [2] f0 d2 }

  condition:
    any of them
}