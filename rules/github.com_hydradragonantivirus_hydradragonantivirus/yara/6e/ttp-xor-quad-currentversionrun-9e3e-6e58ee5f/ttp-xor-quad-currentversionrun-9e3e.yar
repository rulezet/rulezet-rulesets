rule TTP_XOR_QUAD_CurrentVersionRun_9e3e {
  strings:
    $key_9e3e = { cd 51 [2] e9 5f [2] c2 73 [2] ec 51 [2] f8 4a [2] f7 50 [2] e9 4d [2] eb 4c [2] f0 4a [2] ec 4d [2] f0 62 }

  condition:
    any of them
}