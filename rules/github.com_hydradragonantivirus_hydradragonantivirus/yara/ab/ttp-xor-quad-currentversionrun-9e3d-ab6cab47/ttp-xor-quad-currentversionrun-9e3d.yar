rule TTP_XOR_QUAD_CurrentVersionRun_9e3d {
  strings:
    $key_9e3d = { cd 52 [2] e9 5c [2] c2 70 [2] ec 52 [2] f8 49 [2] f7 53 [2] e9 4e [2] eb 4f [2] f0 49 [2] ec 4e [2] f0 61 }

  condition:
    any of them
}