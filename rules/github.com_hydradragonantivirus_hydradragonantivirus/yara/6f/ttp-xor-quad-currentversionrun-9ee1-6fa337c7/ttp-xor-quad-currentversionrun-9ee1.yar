rule TTP_XOR_QUAD_CurrentVersionRun_9ee1 {
  strings:
    $key_9ee1 = { cd 8e [2] e9 80 [2] c2 ac [2] ec 8e [2] f8 95 [2] f7 8f [2] e9 92 [2] eb 93 [2] f0 95 [2] ec 92 [2] f0 bd }

  condition:
    any of them
}