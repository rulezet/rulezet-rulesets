rule TTP_XOR_QUAD_CurrentVersionRun_9e48 {
  strings:
    $key_9e48 = { cd 27 [2] e9 29 [2] c2 05 [2] ec 27 [2] f8 3c [2] f7 26 [2] e9 3b [2] eb 3a [2] f0 3c [2] ec 3b [2] f0 14 }

  condition:
    any of them
}