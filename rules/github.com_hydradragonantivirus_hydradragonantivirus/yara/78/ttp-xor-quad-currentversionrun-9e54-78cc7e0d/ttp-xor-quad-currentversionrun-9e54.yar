rule TTP_XOR_QUAD_CurrentVersionRun_9e54 {
  strings:
    $key_9e54 = { cd 3b [2] e9 35 [2] c2 19 [2] ec 3b [2] f8 20 [2] f7 3a [2] e9 27 [2] eb 26 [2] f0 20 [2] ec 27 [2] f0 08 }

  condition:
    any of them
}