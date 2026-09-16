rule TTP_XOR_QUAD_CurrentVersionRun_9e49 {
  strings:
    $key_9e49 = { cd 26 [2] e9 28 [2] c2 04 [2] ec 26 [2] f8 3d [2] f7 27 [2] e9 3a [2] eb 3b [2] f0 3d [2] ec 3a [2] f0 15 }

  condition:
    any of them
}