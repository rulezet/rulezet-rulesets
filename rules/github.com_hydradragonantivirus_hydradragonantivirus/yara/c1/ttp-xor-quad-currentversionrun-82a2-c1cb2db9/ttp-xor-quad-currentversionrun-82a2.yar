rule TTP_XOR_QUAD_CurrentVersionRun_82a2 {
  strings:
    $key_82a2 = { d1 cd [2] f5 c3 [2] de ef [2] f0 cd [2] e4 d6 [2] eb cc [2] f5 d1 [2] f7 d0 [2] ec d6 [2] f0 d1 [2] ec fe }

  condition:
    any of them
}