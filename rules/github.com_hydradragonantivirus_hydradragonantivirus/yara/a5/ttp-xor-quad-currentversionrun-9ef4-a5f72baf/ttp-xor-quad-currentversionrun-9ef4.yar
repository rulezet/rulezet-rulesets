rule TTP_XOR_QUAD_CurrentVersionRun_9ef4 {
  strings:
    $key_9ef4 = { cd 9b [2] e9 95 [2] c2 b9 [2] ec 9b [2] f8 80 [2] f7 9a [2] e9 87 [2] eb 86 [2] f0 80 [2] ec 87 [2] f0 a8 }

  condition:
    any of them
}