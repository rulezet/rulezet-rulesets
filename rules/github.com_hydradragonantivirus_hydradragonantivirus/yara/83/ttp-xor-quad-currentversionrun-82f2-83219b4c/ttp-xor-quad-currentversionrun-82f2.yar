rule TTP_XOR_QUAD_CurrentVersionRun_82f2 {
  strings:
    $key_82f2 = { d1 9d [2] f5 93 [2] de bf [2] f0 9d [2] e4 86 [2] eb 9c [2] f5 81 [2] f7 80 [2] ec 86 [2] f0 81 [2] ec ae }

  condition:
    any of them
}