rule TTP_XOR_QUAD_CurrentVersionRun_9980 {
  strings:
    $key_9980 = { ca ef [2] ee e1 [2] c5 cd [2] eb ef [2] ff f4 [2] f0 ee [2] ee f3 [2] ec f2 [2] f7 f4 [2] eb f3 [2] f7 dc }

  condition:
    any of them
}