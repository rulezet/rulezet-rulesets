rule TTP_XOR_QUAD_CurrentVersionRun_9ec5 {
  strings:
    $key_9ec5 = { cd aa [2] e9 a4 [2] c2 88 [2] ec aa [2] f8 b1 [2] f7 ab [2] e9 b6 [2] eb b7 [2] f0 b1 [2] ec b6 [2] f0 99 }

  condition:
    any of them
}