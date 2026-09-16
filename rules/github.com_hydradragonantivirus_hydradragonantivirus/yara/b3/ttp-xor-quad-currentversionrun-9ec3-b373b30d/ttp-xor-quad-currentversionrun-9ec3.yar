rule TTP_XOR_QUAD_CurrentVersionRun_9ec3 {
  strings:
    $key_9ec3 = { cd ac [2] e9 a2 [2] c2 8e [2] ec ac [2] f8 b7 [2] f7 ad [2] e9 b0 [2] eb b1 [2] f0 b7 [2] ec b0 [2] f0 9f }

  condition:
    any of them
}