rule TTP_XOR_QUAD_CurrentVersionRun_829b {
  strings:
    $key_829b = { d1 f4 [2] f5 fa [2] de d6 [2] f0 f4 [2] e4 ef [2] eb f5 [2] f5 e8 [2] f7 e9 [2] ec ef [2] f0 e8 [2] ec c7 }

  condition:
    any of them
}