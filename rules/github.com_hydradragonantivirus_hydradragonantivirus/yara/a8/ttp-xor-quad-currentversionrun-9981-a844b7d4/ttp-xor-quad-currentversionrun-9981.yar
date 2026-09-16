rule TTP_XOR_QUAD_CurrentVersionRun_9981 {
  strings:
    $key_9981 = { ca ee [2] ee e0 [2] c5 cc [2] eb ee [2] ff f5 [2] f0 ef [2] ee f2 [2] ec f3 [2] f7 f5 [2] eb f2 [2] f7 dd }

  condition:
    any of them
}