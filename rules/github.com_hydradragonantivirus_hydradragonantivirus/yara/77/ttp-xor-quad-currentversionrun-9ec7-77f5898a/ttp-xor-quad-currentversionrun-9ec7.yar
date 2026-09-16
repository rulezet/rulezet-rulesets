rule TTP_XOR_QUAD_CurrentVersionRun_9ec7 {
  strings:
    $key_9ec7 = { cd a8 [2] e9 a6 [2] c2 8a [2] ec a8 [2] f8 b3 [2] f7 a9 [2] e9 b4 [2] eb b5 [2] f0 b3 [2] ec b4 [2] f0 9b }

  condition:
    any of them
}