rule TTP_XOR_QUAD_CurrentVersionRun_9e47 {
  strings:
    $key_9e47 = { cd 28 [2] e9 26 [2] c2 0a [2] ec 28 [2] f8 33 [2] f7 29 [2] e9 34 [2] eb 35 [2] f0 33 [2] ec 34 [2] f0 1b }

  condition:
    any of them
}