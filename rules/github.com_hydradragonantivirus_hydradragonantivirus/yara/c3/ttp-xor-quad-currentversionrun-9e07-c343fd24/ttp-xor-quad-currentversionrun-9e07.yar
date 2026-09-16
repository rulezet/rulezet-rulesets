rule TTP_XOR_QUAD_CurrentVersionRun_9e07 {
  strings:
    $key_9e07 = { cd 68 [2] e9 66 [2] c2 4a [2] ec 68 [2] f8 73 [2] f7 69 [2] e9 74 [2] eb 75 [2] f0 73 [2] ec 74 [2] f0 5b }

  condition:
    any of them
}