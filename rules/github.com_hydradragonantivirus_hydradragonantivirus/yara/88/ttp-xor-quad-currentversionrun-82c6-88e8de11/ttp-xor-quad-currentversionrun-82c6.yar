rule TTP_XOR_QUAD_CurrentVersionRun_82c6 {
  strings:
    $key_82c6 = { d1 a9 [2] f5 a7 [2] de 8b [2] f0 a9 [2] e4 b2 [2] eb a8 [2] f5 b5 [2] f7 b4 [2] ec b2 [2] f0 b5 [2] ec 9a }

  condition:
    any of them
}