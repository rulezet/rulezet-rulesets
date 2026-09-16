rule TTP_XOR_QUAD_CurrentVersionRun_9e59 {
  strings:
    $key_9e59 = { cd 36 [2] e9 38 [2] c2 14 [2] ec 36 [2] f8 2d [2] f7 37 [2] e9 2a [2] eb 2b [2] f0 2d [2] ec 2a [2] f0 05 }

  condition:
    any of them
}