rule TTP_XOR_QUAD_CurrentVersionRun_82f0 {
  strings:
    $key_82f0 = { d1 9f [2] f5 91 [2] de bd [2] f0 9f [2] e4 84 [2] eb 9e [2] f5 83 [2] f7 82 [2] ec 84 [2] f0 83 [2] ec ac }

  condition:
    any of them
}