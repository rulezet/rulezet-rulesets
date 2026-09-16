rule TTP_XOR_QUAD_CurrentVersionRun_9e0f {
  strings:
    $key_9e0f = { cd 60 [2] e9 6e [2] c2 42 [2] ec 60 [2] f8 7b [2] f7 61 [2] e9 7c [2] eb 7d [2] f0 7b [2] ec 7c [2] f0 53 }

  condition:
    any of them
}