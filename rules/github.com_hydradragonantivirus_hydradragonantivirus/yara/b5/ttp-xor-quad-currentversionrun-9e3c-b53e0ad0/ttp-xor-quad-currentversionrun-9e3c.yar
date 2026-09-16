rule TTP_XOR_QUAD_CurrentVersionRun_9e3c {
  strings:
    $key_9e3c = { cd 53 [2] e9 5d [2] c2 71 [2] ec 53 [2] f8 48 [2] f7 52 [2] e9 4f [2] eb 4e [2] f0 48 [2] ec 4f [2] f0 60 }

  condition:
    any of them
}