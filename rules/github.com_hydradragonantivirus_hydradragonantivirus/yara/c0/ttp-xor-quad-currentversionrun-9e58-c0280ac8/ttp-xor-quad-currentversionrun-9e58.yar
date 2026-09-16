rule TTP_XOR_QUAD_CurrentVersionRun_9e58 {
  strings:
    $key_9e58 = { cd 37 [2] e9 39 [2] c2 15 [2] ec 37 [2] f8 2c [2] f7 36 [2] e9 2b [2] eb 2a [2] f0 2c [2] ec 2b [2] f0 04 }

  condition:
    any of them
}