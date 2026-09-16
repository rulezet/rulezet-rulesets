rule TTP_XOR_QUAD_CurrentVersionRun_82e2 {
  strings:
    $key_82e2 = { d1 8d [2] f5 83 [2] de af [2] f0 8d [2] e4 96 [2] eb 8c [2] f5 91 [2] f7 90 [2] ec 96 [2] f0 91 [2] ec be }

  condition:
    any of them
}