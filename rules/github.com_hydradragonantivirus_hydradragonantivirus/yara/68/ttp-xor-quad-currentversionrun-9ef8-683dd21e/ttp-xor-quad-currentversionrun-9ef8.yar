rule TTP_XOR_QUAD_CurrentVersionRun_9ef8 {
  strings:
    $key_9ef8 = { cd 97 [2] e9 99 [2] c2 b5 [2] ec 97 [2] f8 8c [2] f7 96 [2] e9 8b [2] eb 8a [2] f0 8c [2] ec 8b [2] f0 a4 }

  condition:
    any of them
}