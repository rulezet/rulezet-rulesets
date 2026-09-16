rule TTP_XOR_QUAD_CurrentVersionRun_82ec {
  strings:
    $key_82ec = { d1 83 [2] f5 8d [2] de a1 [2] f0 83 [2] e4 98 [2] eb 82 [2] f5 9f [2] f7 9e [2] ec 98 [2] f0 9f [2] ec b0 }

  condition:
    any of them
}