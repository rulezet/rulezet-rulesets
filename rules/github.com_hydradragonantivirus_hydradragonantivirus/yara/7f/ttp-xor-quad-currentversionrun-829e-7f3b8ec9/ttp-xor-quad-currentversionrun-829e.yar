rule TTP_XOR_QUAD_CurrentVersionRun_829e {
  strings:
    $key_829e = { d1 f1 [2] f5 ff [2] de d3 [2] f0 f1 [2] e4 ea [2] eb f0 [2] f5 ed [2] f7 ec [2] ec ea [2] f0 ed [2] ec c2 }

  condition:
    any of them
}