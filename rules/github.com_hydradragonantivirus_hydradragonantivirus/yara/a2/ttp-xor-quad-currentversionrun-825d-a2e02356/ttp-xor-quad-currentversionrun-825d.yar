rule TTP_XOR_QUAD_CurrentVersionRun_825d {
  strings:
    $key_825d = { d1 32 [2] f5 3c [2] de 10 [2] f0 32 [2] e4 29 [2] eb 33 [2] f5 2e [2] f7 2f [2] ec 29 [2] f0 2e [2] ec 01 }

  condition:
    any of them
}