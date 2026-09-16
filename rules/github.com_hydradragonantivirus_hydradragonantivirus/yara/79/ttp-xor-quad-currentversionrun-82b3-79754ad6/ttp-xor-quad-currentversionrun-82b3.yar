rule TTP_XOR_QUAD_CurrentVersionRun_82b3 {
  strings:
    $key_82b3 = { d1 dc [2] f5 d2 [2] de fe [2] f0 dc [2] e4 c7 [2] eb dd [2] f5 c0 [2] f7 c1 [2] ec c7 [2] f0 c0 [2] ec ef }

  condition:
    any of them
}