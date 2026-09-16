rule TTP_XOR_QUAD_CurrentVersionRun_9e87 {
  strings:
    $key_9e87 = { cd e8 [2] e9 e6 [2] c2 ca [2] ec e8 [2] f8 f3 [2] f7 e9 [2] e9 f4 [2] eb f5 [2] f0 f3 [2] ec f4 [2] f0 db }

  condition:
    any of them
}