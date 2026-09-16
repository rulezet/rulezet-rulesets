rule TTP_XOR_QUAD_CurrentVersionRun_825f {
  strings:
    $key_825f = { d1 30 [2] f5 3e [2] de 12 [2] f0 30 [2] e4 2b [2] eb 31 [2] f5 2c [2] f7 2d [2] ec 2b [2] f0 2c [2] ec 03 }

  condition:
    any of them
}