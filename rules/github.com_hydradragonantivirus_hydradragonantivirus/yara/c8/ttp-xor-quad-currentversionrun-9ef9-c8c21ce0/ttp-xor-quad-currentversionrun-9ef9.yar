rule TTP_XOR_QUAD_CurrentVersionRun_9ef9 {
  strings:
    $key_9ef9 = { cd 96 [2] e9 98 [2] c2 b4 [2] ec 96 [2] f8 8d [2] f7 97 [2] e9 8a [2] eb 8b [2] f0 8d [2] ec 8a [2] f0 a5 }

  condition:
    any of them
}