rule TTP_XOR_QUAD_CurrentVersionRun_9e16 {
  strings:
    $key_9e16 = { cd 79 [2] e9 77 [2] c2 5b [2] ec 79 [2] f8 62 [2] f7 78 [2] e9 65 [2] eb 64 [2] f0 62 [2] ec 65 [2] f0 4a }

  condition:
    any of them
}