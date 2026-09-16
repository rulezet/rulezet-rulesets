rule TTP_XOR_QUAD_CurrentVersionRun_9ea6 {
  strings:
    $key_9ea6 = { cd c9 [2] e9 c7 [2] c2 eb [2] ec c9 [2] f8 d2 [2] f7 c8 [2] e9 d5 [2] eb d4 [2] f0 d2 [2] ec d5 [2] f0 fa }

  condition:
    any of them
}