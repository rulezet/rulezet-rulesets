rule TTP_XOR_QUAD_CurrentVersionRun_9e31 {
  strings:
    $key_9e31 = { cd 5e [2] e9 50 [2] c2 7c [2] ec 5e [2] f8 45 [2] f7 5f [2] e9 42 [2] eb 43 [2] f0 45 [2] ec 42 [2] f0 6d }

  condition:
    any of them
}