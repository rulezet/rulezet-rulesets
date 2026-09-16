rule TTP_XOR_QUAD_CurrentVersionRun_9e44 {
  strings:
    $key_9e44 = { cd 2b [2] e9 25 [2] c2 09 [2] ec 2b [2] f8 30 [2] f7 2a [2] e9 37 [2] eb 36 [2] f0 30 [2] ec 37 [2] f0 18 }

  condition:
    any of them
}