rule TTP_XOR_QUAD_CurrentVersionRun_9edf {
  strings:
    $key_9edf = { cd b0 [2] e9 be [2] c2 92 [2] ec b0 [2] f8 ab [2] f7 b1 [2] e9 ac [2] eb ad [2] f0 ab [2] ec ac [2] f0 83 }

  condition:
    any of them
}