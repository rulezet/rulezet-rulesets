rule TTP_XOR_QUAD_CurrentVersionRun_829a {
  strings:
    $key_829a = { d1 f5 [2] f5 fb [2] de d7 [2] f0 f5 [2] e4 ee [2] eb f4 [2] f5 e9 [2] f7 e8 [2] ec ee [2] f0 e9 [2] ec c6 }

  condition:
    any of them
}