rule TTP_XOR_QUAD_CurrentVersionRun_9e39 {
  strings:
    $key_9e39 = { cd 56 [2] e9 58 [2] c2 74 [2] ec 56 [2] f8 4d [2] f7 57 [2] e9 4a [2] eb 4b [2] f0 4d [2] ec 4a [2] f0 65 }

  condition:
    any of them
}