rule TTP_XOR_QUAD_CurrentVersionRun_824c {
  strings:
    $key_824c = { d1 23 [2] f5 2d [2] de 01 [2] f0 23 [2] e4 38 [2] eb 22 [2] f5 3f [2] f7 3e [2] ec 38 [2] f0 3f [2] ec 10 }

  condition:
    any of them
}