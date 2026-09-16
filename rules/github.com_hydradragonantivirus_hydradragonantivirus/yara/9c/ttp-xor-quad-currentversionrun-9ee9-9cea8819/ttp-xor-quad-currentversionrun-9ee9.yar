rule TTP_XOR_QUAD_CurrentVersionRun_9ee9 {
  strings:
    $key_9ee9 = { cd 86 [2] e9 88 [2] c2 a4 [2] ec 86 [2] f8 9d [2] f7 87 [2] e9 9a [2] eb 9b [2] f0 9d [2] ec 9a [2] f0 b5 }

  condition:
    any of them
}