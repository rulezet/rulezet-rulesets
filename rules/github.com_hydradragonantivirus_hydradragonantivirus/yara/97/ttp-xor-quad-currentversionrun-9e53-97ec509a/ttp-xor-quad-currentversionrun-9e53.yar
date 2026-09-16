rule TTP_XOR_QUAD_CurrentVersionRun_9e53 {
  strings:
    $key_9e53 = { cd 3c [2] e9 32 [2] c2 1e [2] ec 3c [2] f8 27 [2] f7 3d [2] e9 20 [2] eb 21 [2] f0 27 [2] ec 20 [2] f0 0f }

  condition:
    any of them
}