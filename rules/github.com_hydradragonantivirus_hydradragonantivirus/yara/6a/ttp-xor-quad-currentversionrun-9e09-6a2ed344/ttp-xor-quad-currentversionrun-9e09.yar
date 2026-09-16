rule TTP_XOR_QUAD_CurrentVersionRun_9e09 {
  strings:
    $key_9e09 = { cd 66 [2] e9 68 [2] c2 44 [2] ec 66 [2] f8 7d [2] f7 67 [2] e9 7a [2] eb 7b [2] f0 7d [2] ec 7a [2] f0 55 }

  condition:
    any of them
}