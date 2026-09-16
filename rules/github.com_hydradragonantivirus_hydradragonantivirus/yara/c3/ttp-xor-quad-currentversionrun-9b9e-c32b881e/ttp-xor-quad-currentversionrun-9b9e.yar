rule TTP_XOR_QUAD_CurrentVersionRun_9b9e {
  strings:
    $key_9b9e = { c8 f1 [2] ec ff [2] c7 d3 [2] e9 f1 [2] fd ea [2] f2 f0 [2] ec ed [2] ee ec [2] f5 ea [2] e9 ed [2] f5 c2 }

  condition:
    any of them
}