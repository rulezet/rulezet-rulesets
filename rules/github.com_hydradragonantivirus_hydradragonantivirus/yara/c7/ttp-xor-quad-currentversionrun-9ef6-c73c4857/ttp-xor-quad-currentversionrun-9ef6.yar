rule TTP_XOR_QUAD_CurrentVersionRun_9ef6 {
  strings:
    $key_9ef6 = { cd 99 [2] e9 97 [2] c2 bb [2] ec 99 [2] f8 82 [2] f7 98 [2] e9 85 [2] eb 84 [2] f0 82 [2] ec 85 [2] f0 aa }

  condition:
    any of them
}