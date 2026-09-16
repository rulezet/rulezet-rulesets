rule TTP_XOR_QUAD_CurrentVersionRun_9e63 {
  strings:
    $key_9e63 = { cd 0c [2] e9 02 [2] c2 2e [2] ec 0c [2] f8 17 [2] f7 0d [2] e9 10 [2] eb 11 [2] f0 17 [2] ec 10 [2] f0 3f }

  condition:
    any of them
}