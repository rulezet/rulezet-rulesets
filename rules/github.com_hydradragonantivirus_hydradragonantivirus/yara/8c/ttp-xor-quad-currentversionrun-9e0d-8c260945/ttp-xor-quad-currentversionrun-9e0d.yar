rule TTP_XOR_QUAD_CurrentVersionRun_9e0d {
  strings:
    $key_9e0d = { cd 62 [2] e9 6c [2] c2 40 [2] ec 62 [2] f8 79 [2] f7 63 [2] e9 7e [2] eb 7f [2] f0 79 [2] ec 7e [2] f0 51 }

  condition:
    any of them
}