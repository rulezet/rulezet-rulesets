rule TTP_XOR_QUAD_CurrentVersionRun_82b6 {
  strings:
    $key_82b6 = { d1 d9 [2] f5 d7 [2] de fb [2] f0 d9 [2] e4 c2 [2] eb d8 [2] f5 c5 [2] f7 c4 [2] ec c2 [2] f0 c5 [2] ec ea }

  condition:
    any of them
}