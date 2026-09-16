rule TTP_XOR_QUAD_CurrentVersionRun_9984 {
  strings:
    $key_9984 = { ca eb [2] ee e5 [2] c5 c9 [2] eb eb [2] ff f0 [2] f0 ea [2] ee f7 [2] ec f6 [2] f7 f0 [2] eb f7 [2] f7 d8 }

  condition:
    any of them
}