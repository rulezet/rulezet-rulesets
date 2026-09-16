rule TTP_XOR_QUAD_CurrentVersionRun_9e0e {
  strings:
    $key_9e0e = { cd 61 [2] e9 6f [2] c2 43 [2] ec 61 [2] f8 7a [2] f7 60 [2] e9 7d [2] eb 7c [2] f0 7a [2] ec 7d [2] f0 52 }

  condition:
    any of them
}