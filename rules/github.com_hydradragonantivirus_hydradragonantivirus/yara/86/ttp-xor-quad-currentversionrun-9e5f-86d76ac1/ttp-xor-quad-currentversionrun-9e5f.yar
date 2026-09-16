rule TTP_XOR_QUAD_CurrentVersionRun_9e5f {
  strings:
    $key_9e5f = { cd 30 [2] e9 3e [2] c2 12 [2] ec 30 [2] f8 2b [2] f7 31 [2] e9 2c [2] eb 2d [2] f0 2b [2] ec 2c [2] f0 03 }

  condition:
    any of them
}