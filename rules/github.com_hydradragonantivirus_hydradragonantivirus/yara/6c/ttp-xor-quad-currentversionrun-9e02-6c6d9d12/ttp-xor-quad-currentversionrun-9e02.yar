rule TTP_XOR_QUAD_CurrentVersionRun_9e02 {
  strings:
    $key_9e02 = { cd 6d [2] e9 63 [2] c2 4f [2] ec 6d [2] f8 76 [2] f7 6c [2] e9 71 [2] eb 70 [2] f0 76 [2] ec 71 [2] f0 5e }

  condition:
    any of them
}