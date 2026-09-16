rule TTP_XOR_QUAD_CurrentVersionRun_9ec6 {
  strings:
    $key_9ec6 = { cd a9 [2] e9 a7 [2] c2 8b [2] ec a9 [2] f8 b2 [2] f7 a8 [2] e9 b5 [2] eb b4 [2] f0 b2 [2] ec b5 [2] f0 9a }

  condition:
    any of them
}