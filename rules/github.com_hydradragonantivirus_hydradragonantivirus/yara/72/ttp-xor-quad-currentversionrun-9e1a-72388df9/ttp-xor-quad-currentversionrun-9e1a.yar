rule TTP_XOR_QUAD_CurrentVersionRun_9e1a {
  strings:
    $key_9e1a = { cd 75 [2] e9 7b [2] c2 57 [2] ec 75 [2] f8 6e [2] f7 74 [2] e9 69 [2] eb 68 [2] f0 6e [2] ec 69 [2] f0 46 }

  condition:
    any of them
}