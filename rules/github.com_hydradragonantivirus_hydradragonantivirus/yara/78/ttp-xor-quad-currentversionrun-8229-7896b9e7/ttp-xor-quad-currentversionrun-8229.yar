rule TTP_XOR_QUAD_CurrentVersionRun_8229 {
  strings:
    $key_8229 = { d1 46 [2] f5 48 [2] de 64 [2] f0 46 [2] e4 5d [2] eb 47 [2] f5 5a [2] f7 5b [2] ec 5d [2] f0 5a [2] ec 75 }

  condition:
    any of them
}