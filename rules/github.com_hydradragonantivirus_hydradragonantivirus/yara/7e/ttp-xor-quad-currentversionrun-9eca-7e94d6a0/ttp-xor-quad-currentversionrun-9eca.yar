rule TTP_XOR_QUAD_CurrentVersionRun_9eca {
  strings:
    $key_9eca = { cd a5 [2] e9 ab [2] c2 87 [2] ec a5 [2] f8 be [2] f7 a4 [2] e9 b9 [2] eb b8 [2] f0 be [2] ec b9 [2] f0 96 }

  condition:
    any of them
}