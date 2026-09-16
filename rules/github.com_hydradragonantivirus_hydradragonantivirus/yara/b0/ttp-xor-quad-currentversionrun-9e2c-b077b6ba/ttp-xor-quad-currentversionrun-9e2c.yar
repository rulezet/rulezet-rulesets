rule TTP_XOR_QUAD_CurrentVersionRun_9e2c {
  strings:
    $key_9e2c = { cd 43 [2] e9 4d [2] c2 61 [2] ec 43 [2] f8 58 [2] f7 42 [2] e9 5f [2] eb 5e [2] f0 58 [2] ec 5f [2] f0 70 }

  condition:
    any of them
}