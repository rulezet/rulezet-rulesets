rule TTP_XOR_QUAD_CurrentVersionRun_82ef {
  strings:
    $key_82ef = { d1 80 [2] f5 8e [2] de a2 [2] f0 80 [2] e4 9b [2] eb 81 [2] f5 9c [2] f7 9d [2] ec 9b [2] f0 9c [2] ec b3 }

  condition:
    any of them
}