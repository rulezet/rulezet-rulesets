rule TTP_XOR_QUAD_CurrentVersionRun_9efa {
  strings:
    $key_9efa = { cd 95 [2] e9 9b [2] c2 b7 [2] ec 95 [2] f8 8e [2] f7 94 [2] e9 89 [2] eb 88 [2] f0 8e [2] ec 89 [2] f0 a6 }

  condition:
    any of them
}