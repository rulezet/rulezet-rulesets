rule TTP_XOR_QUAD_CurrentVersionRun_9e29 {
  strings:
    $key_9e29 = { cd 46 [2] e9 48 [2] c2 64 [2] ec 46 [2] f8 5d [2] f7 47 [2] e9 5a [2] eb 5b [2] f0 5d [2] ec 5a [2] f0 75 }

  condition:
    any of them
}