rule TTP_XOR_QUAD_CurrentVersionRun_8269 {
  strings:
    $key_8269 = { d1 06 [2] f5 08 [2] de 24 [2] f0 06 [2] e4 1d [2] eb 07 [2] f5 1a [2] f7 1b [2] ec 1d [2] f0 1a [2] ec 35 }

  condition:
    any of them
}