rule TTP_XOR_QUAD_CurrentVersionRun_9e60 {
  strings:
    $key_9e60 = { cd 0f [2] e9 01 [2] c2 2d [2] ec 0f [2] f8 14 [2] f7 0e [2] e9 13 [2] eb 12 [2] f0 14 [2] ec 13 [2] f0 3c }

  condition:
    any of them
}