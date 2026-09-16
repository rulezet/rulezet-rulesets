rule TTP_XOR_QUAD_CurrentVersionRun_9e83 {
  strings:
    $key_9e83 = { cd ec [2] e9 e2 [2] c2 ce [2] ec ec [2] f8 f7 [2] f7 ed [2] e9 f0 [2] eb f1 [2] f0 f7 [2] ec f0 [2] f0 df }

  condition:
    any of them
}