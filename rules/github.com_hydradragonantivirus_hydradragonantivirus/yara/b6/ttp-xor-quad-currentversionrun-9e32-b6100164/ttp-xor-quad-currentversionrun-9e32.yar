rule TTP_XOR_QUAD_CurrentVersionRun_9e32 {
  strings:
    $key_9e32 = { cd 5d [2] e9 53 [2] c2 7f [2] ec 5d [2] f8 46 [2] f7 5c [2] e9 41 [2] eb 40 [2] f0 46 [2] ec 41 [2] f0 6e }

  condition:
    any of them
}