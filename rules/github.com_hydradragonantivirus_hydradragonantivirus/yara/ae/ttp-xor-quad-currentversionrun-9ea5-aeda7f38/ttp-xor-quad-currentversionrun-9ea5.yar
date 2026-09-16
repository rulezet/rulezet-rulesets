rule TTP_XOR_QUAD_CurrentVersionRun_9ea5 {
  strings:
    $key_9ea5 = { cd ca [2] e9 c4 [2] c2 e8 [2] ec ca [2] f8 d1 [2] f7 cb [2] e9 d6 [2] eb d7 [2] f0 d1 [2] ec d6 [2] f0 f9 }

  condition:
    any of them
}