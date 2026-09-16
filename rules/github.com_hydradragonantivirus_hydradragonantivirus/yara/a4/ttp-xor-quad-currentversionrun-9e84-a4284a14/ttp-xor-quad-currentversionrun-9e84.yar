rule TTP_XOR_QUAD_CurrentVersionRun_9e84 {
  strings:
    $key_9e84 = { cd eb [2] e9 e5 [2] c2 c9 [2] ec eb [2] f8 f0 [2] f7 ea [2] e9 f7 [2] eb f6 [2] f0 f0 [2] ec f7 [2] f0 d8 }

  condition:
    any of them
}