rule TTP_XOR_QUAD_CurrentVersionRun_82c0 {
  strings:
    $key_82c0 = { d1 af [2] f5 a1 [2] de 8d [2] f0 af [2] e4 b4 [2] eb ae [2] f5 b3 [2] f7 b2 [2] ec b4 [2] f0 b3 [2] ec 9c }

  condition:
    any of them
}