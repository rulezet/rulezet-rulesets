rule TTP_XOR_QUAD_CurrentVersionRun_825a {
  strings:
    $key_825a = { d1 35 [2] f5 3b [2] de 17 [2] f0 35 [2] e4 2e [2] eb 34 [2] f5 29 [2] f7 28 [2] ec 2e [2] f0 29 [2] ec 06 }

  condition:
    any of them
}