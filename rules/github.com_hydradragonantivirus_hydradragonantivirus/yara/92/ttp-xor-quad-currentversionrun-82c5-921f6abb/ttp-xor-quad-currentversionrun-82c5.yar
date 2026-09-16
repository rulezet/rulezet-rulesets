rule TTP_XOR_QUAD_CurrentVersionRun_82c5 {
  strings:
    $key_82c5 = { d1 aa [2] f5 a4 [2] de 88 [2] f0 aa [2] e4 b1 [2] eb ab [2] f5 b6 [2] f7 b7 [2] ec b1 [2] f0 b6 [2] ec 99 }

  condition:
    any of them
}