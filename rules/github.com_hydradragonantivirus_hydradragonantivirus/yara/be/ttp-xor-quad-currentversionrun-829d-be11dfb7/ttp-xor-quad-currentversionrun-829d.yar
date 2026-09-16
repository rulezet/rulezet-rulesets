rule TTP_XOR_QUAD_CurrentVersionRun_829d {
  strings:
    $key_829d = { d1 f2 [2] f5 fc [2] de d0 [2] f0 f2 [2] e4 e9 [2] eb f3 [2] f5 ee [2] f7 ef [2] ec e9 [2] f0 ee [2] ec c1 }

  condition:
    any of them
}