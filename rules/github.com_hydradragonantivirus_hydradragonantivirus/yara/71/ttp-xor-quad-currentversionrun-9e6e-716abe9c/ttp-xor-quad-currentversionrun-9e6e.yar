rule TTP_XOR_QUAD_CurrentVersionRun_9e6e {
  strings:
    $key_9e6e = { cd 01 [2] e9 0f [2] c2 23 [2] ec 01 [2] f8 1a [2] f7 00 [2] e9 1d [2] eb 1c [2] f0 1a [2] ec 1d [2] f0 32 }

  condition:
    any of them
}