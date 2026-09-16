rule TTP_XOR_QUAD_CurrentVersionRun_9e0b {
  strings:
    $key_9e0b = { cd 64 [2] e9 6a [2] c2 46 [2] ec 64 [2] f8 7f [2] f7 65 [2] e9 78 [2] eb 79 [2] f0 7f [2] ec 78 [2] f0 57 }

  condition:
    any of them
}