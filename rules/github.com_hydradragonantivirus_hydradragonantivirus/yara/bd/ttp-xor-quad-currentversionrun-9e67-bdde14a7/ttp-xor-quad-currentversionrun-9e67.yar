rule TTP_XOR_QUAD_CurrentVersionRun_9e67 {
  strings:
    $key_9e67 = { cd 08 [2] e9 06 [2] c2 2a [2] ec 08 [2] f8 13 [2] f7 09 [2] e9 14 [2] eb 15 [2] f0 13 [2] ec 14 [2] f0 3b }

  condition:
    any of them
}