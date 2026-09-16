rule TTP_XOR_QUAD_CurrentVersionRun_8a9e {
  strings:
    $key_8a9e = { d9 f1 [2] fd ff [2] d6 d3 [2] f8 f1 [2] ec ea [2] e3 f0 [2] fd ed [2] ff ec [2] e4 ea [2] f8 ed [2] e4 c2 }

  condition:
    any of them
}