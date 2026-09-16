rule TTP_XOR_QUAD_CurrentVersionRun_9e25 {
  strings:
    $key_9e25 = { cd 4a [2] e9 44 [2] c2 68 [2] ec 4a [2] f8 51 [2] f7 4b [2] e9 56 [2] eb 57 [2] f0 51 [2] ec 56 [2] f0 79 }

  condition:
    any of them
}