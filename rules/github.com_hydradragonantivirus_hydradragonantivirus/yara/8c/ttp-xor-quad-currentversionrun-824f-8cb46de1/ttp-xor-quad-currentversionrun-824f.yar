rule TTP_XOR_QUAD_CurrentVersionRun_824f {
  strings:
    $key_824f = { d1 20 [2] f5 2e [2] de 02 [2] f0 20 [2] e4 3b [2] eb 21 [2] f5 3c [2] f7 3d [2] ec 3b [2] f0 3c [2] ec 13 }

  condition:
    any of them
}