rule TTP_XOR_QUAD_CurrentVersionRun_82f3 {
  strings:
    $key_82f3 = { d1 9c [2] f5 92 [2] de be [2] f0 9c [2] e4 87 [2] eb 9d [2] f5 80 [2] f7 81 [2] ec 87 [2] f0 80 [2] ec af }

  condition:
    any of them
}