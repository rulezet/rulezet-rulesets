rule TTP_XOR_QUAD_CurrentVersionRun_9e2d {
  strings:
    $key_9e2d = { cd 42 [2] e9 4c [2] c2 60 [2] ec 42 [2] f8 59 [2] f7 43 [2] e9 5e [2] eb 5f [2] f0 59 [2] ec 5e [2] f0 71 }

  condition:
    any of them
}