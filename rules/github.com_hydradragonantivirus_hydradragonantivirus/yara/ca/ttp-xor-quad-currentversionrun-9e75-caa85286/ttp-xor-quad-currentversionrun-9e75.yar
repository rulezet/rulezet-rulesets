rule TTP_XOR_QUAD_CurrentVersionRun_9e75 {
  strings:
    $key_9e75 = { cd 1a [2] e9 14 [2] c2 38 [2] ec 1a [2] f8 01 [2] f7 1b [2] e9 06 [2] eb 07 [2] f0 01 [2] ec 06 [2] f0 29 }

  condition:
    any of them
}