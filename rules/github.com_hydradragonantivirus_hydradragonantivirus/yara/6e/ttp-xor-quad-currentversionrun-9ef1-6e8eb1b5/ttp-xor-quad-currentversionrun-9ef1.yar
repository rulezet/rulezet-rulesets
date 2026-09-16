rule TTP_XOR_QUAD_CurrentVersionRun_9ef1 {
  strings:
    $key_9ef1 = { cd 9e [2] e9 90 [2] c2 bc [2] ec 9e [2] f8 85 [2] f7 9f [2] e9 82 [2] eb 83 [2] f0 85 [2] ec 82 [2] f0 ad }

  condition:
    any of them
}