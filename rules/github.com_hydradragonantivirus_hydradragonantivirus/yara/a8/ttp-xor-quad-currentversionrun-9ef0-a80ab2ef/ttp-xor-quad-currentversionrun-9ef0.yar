rule TTP_XOR_QUAD_CurrentVersionRun_9ef0 {
  strings:
    $key_9ef0 = { cd 9f [2] e9 91 [2] c2 bd [2] ec 9f [2] f8 84 [2] f7 9e [2] e9 83 [2] eb 82 [2] f0 84 [2] ec 83 [2] f0 ac }

  condition:
    any of them
}