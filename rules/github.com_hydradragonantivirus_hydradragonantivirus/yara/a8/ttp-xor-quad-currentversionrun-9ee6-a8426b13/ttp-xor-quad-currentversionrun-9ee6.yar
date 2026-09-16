rule TTP_XOR_QUAD_CurrentVersionRun_9ee6 {
  strings:
    $key_9ee6 = { cd 89 [2] e9 87 [2] c2 ab [2] ec 89 [2] f8 92 [2] f7 88 [2] e9 95 [2] eb 94 [2] f0 92 [2] ec 95 [2] f0 ba }

  condition:
    any of them
}