rule TTP_XOR_QUAD_CurrentVersionRun_9ec4 {
  strings:
    $key_9ec4 = { cd ab [2] e9 a5 [2] c2 89 [2] ec ab [2] f8 b0 [2] f7 aa [2] e9 b7 [2] eb b6 [2] f0 b0 [2] ec b7 [2] f0 98 }

  condition:
    any of them
}