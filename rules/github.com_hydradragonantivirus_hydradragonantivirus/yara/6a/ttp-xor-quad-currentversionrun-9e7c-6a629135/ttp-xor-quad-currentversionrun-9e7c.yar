rule TTP_XOR_QUAD_CurrentVersionRun_9e7c {
  strings:
    $key_9e7c = { cd 13 [2] e9 1d [2] c2 31 [2] ec 13 [2] f8 08 [2] f7 12 [2] e9 0f [2] eb 0e [2] f0 08 [2] ec 0f [2] f0 20 }

  condition:
    any of them
}