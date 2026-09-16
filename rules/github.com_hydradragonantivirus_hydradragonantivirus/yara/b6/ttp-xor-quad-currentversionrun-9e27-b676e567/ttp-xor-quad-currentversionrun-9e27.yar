rule TTP_XOR_QUAD_CurrentVersionRun_9e27 {
  strings:
    $key_9e27 = { cd 48 [2] e9 46 [2] c2 6a [2] ec 48 [2] f8 53 [2] f7 49 [2] e9 54 [2] eb 55 [2] f0 53 [2] ec 54 [2] f0 7b }

  condition:
    any of them
}