rule TTP_XOR_QUAD_CurrentVersionRun_9e5e {
  strings:
    $key_9e5e = { cd 31 [2] e9 3f [2] c2 13 [2] ec 31 [2] f8 2a [2] f7 30 [2] e9 2d [2] eb 2c [2] f0 2a [2] ec 2d [2] f0 02 }

  condition:
    any of them
}