rule TTP_XOR_QUAD_CurrentVersionRun_9eef {
  strings:
    $key_9eef = { cd 80 [2] e9 8e [2] c2 a2 [2] ec 80 [2] f8 9b [2] f7 81 [2] e9 9c [2] eb 9d [2] f0 9b [2] ec 9c [2] f0 b3 }

  condition:
    any of them
}