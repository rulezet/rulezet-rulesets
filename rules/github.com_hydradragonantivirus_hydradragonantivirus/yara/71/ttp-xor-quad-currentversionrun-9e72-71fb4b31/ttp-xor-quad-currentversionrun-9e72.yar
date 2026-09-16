rule TTP_XOR_QUAD_CurrentVersionRun_9e72 {
  strings:
    $key_9e72 = { cd 1d [2] e9 13 [2] c2 3f [2] ec 1d [2] f8 06 [2] f7 1c [2] e9 01 [2] eb 00 [2] f0 06 [2] ec 01 [2] f0 2e }

  condition:
    any of them
}