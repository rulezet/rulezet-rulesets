rule TTP_XOR_QUAD_CurrentVersionRun_82f6 {
  strings:
    $key_82f6 = { d1 99 [2] f5 97 [2] de bb [2] f0 99 [2] e4 82 [2] eb 98 [2] f5 85 [2] f7 84 [2] ec 82 [2] f0 85 [2] ec aa }

  condition:
    any of them
}