rule TTP_XOR_QUAD_CurrentVersionRun_825c {
  strings:
    $key_825c = { d1 33 [2] f5 3d [2] de 11 [2] f0 33 [2] e4 28 [2] eb 32 [2] f5 2f [2] f7 2e [2] ec 28 [2] f0 2f [2] ec 00 }

  condition:
    any of them
}