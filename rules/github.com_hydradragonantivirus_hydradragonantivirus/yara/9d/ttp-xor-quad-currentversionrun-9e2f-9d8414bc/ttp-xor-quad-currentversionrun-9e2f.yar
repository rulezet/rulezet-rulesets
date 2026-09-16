rule TTP_XOR_QUAD_CurrentVersionRun_9e2f {
  strings:
    $key_9e2f = { cd 40 [2] e9 4e [2] c2 62 [2] ec 40 [2] f8 5b [2] f7 41 [2] e9 5c [2] eb 5d [2] f0 5b [2] ec 5c [2] f0 73 }

  condition:
    any of them
}