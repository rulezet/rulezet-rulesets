rule TTP_XOR_QUAD_CurrentVersionRun_9983 {
  strings:
    $key_9983 = { ca ec [2] ee e2 [2] c5 ce [2] eb ec [2] ff f7 [2] f0 ed [2] ee f0 [2] ec f1 [2] f7 f7 [2] eb f0 [2] f7 df }

  condition:
    any of them
}