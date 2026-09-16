rule TTP_XOR_QUAD_CurrentVersionRun_82c4 {
  strings:
    $key_82c4 = { d1 ab [2] f5 a5 [2] de 89 [2] f0 ab [2] e4 b0 [2] eb aa [2] f5 b7 [2] f7 b6 [2] ec b0 [2] f0 b7 [2] ec 98 }

  condition:
    any of them
}