rule TTP_XOR_QUAD_CurrentVersionRun_9e5d {
  strings:
    $key_9e5d = { cd 32 [2] e9 3c [2] c2 10 [2] ec 32 [2] f8 29 [2] f7 33 [2] e9 2e [2] eb 2f [2] f0 29 [2] ec 2e [2] f0 01 }

  condition:
    any of them
}