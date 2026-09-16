rule TTP_XOR_QUAD_CurrentVersionRun_9e0a {
  strings:
    $key_9e0a = { cd 65 [2] e9 6b [2] c2 47 [2] ec 65 [2] f8 7e [2] f7 64 [2] e9 79 [2] eb 78 [2] f0 7e [2] ec 79 [2] f0 56 }

  condition:
    any of them
}