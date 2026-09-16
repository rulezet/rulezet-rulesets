rule TTP_XOR_QUAD_CurrentVersionRun_9e22 {
  strings:
    $key_9e22 = { cd 4d [2] e9 43 [2] c2 6f [2] ec 4d [2] f8 56 [2] f7 4c [2] e9 51 [2] eb 50 [2] f0 56 [2] ec 51 [2] f0 7e }

  condition:
    any of them
}