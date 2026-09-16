rule TTP_XOR_QUAD_CurrentVersionRun_9e43 {
  strings:
    $key_9e43 = { cd 2c [2] e9 22 [2] c2 0e [2] ec 2c [2] f8 37 [2] f7 2d [2] e9 30 [2] eb 31 [2] f0 37 [2] ec 30 [2] f0 1f }

  condition:
    any of them
}