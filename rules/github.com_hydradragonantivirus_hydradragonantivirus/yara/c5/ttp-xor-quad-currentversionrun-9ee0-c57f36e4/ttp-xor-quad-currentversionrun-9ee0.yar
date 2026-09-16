rule TTP_XOR_QUAD_CurrentVersionRun_9ee0 {
  strings:
    $key_9ee0 = { cd 8f [2] e9 81 [2] c2 ad [2] ec 8f [2] f8 94 [2] f7 8e [2] e9 93 [2] eb 92 [2] f0 94 [2] ec 93 [2] f0 bc }

  condition:
    any of them
}