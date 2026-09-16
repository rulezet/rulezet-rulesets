rule TTP_XOR_QUAD_CurrentVersionRun_9e66 {
  strings:
    $key_9e66 = { cd 09 [2] e9 07 [2] c2 2b [2] ec 09 [2] f8 12 [2] f7 08 [2] e9 15 [2] eb 14 [2] f0 12 [2] ec 15 [2] f0 3a }

  condition:
    any of them
}