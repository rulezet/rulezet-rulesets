rule TTP_XOR_QUAD_CurrentVersionRun_9ec0 {
  strings:
    $key_9ec0 = { cd af [2] e9 a1 [2] c2 8d [2] ec af [2] f8 b4 [2] f7 ae [2] e9 b3 [2] eb b2 [2] f0 b4 [2] ec b3 [2] f0 9c }

  condition:
    any of them
}