rule TTP_XOR_QUAD_CurrentVersionRun_826f {
  strings:
    $key_826f = { d1 00 [2] f5 0e [2] de 22 [2] f0 00 [2] e4 1b [2] eb 01 [2] f5 1c [2] f7 1d [2] ec 1b [2] f0 1c [2] ec 33 }

  condition:
    any of them
}