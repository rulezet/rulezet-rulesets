rule TTP_XOR_QUAD_CurrentVersionRun_859e {
  strings:
    $key_859e = { d6 f1 [2] f2 ff [2] d9 d3 [2] f7 f1 [2] e3 ea [2] ec f0 [2] f2 ed [2] f0 ec [2] eb ea [2] f7 ed [2] eb c2 }

  condition:
    any of them
}