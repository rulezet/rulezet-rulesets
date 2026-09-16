rule TTP_XOR_QUAD_CurrentVersionRun_9e50 {
  strings:
    $key_9e50 = { cd 3f [2] e9 31 [2] c2 1d [2] ec 3f [2] f8 24 [2] f7 3e [2] e9 23 [2] eb 22 [2] f0 24 [2] ec 23 [2] f0 0c }

  condition:
    any of them
}