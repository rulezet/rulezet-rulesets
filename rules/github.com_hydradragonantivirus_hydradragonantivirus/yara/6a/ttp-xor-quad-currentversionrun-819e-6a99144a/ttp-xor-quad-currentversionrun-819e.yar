rule TTP_XOR_QUAD_CurrentVersionRun_819e {
  strings:
    $key_819e = { d2 f1 [2] f6 ff [2] dd d3 [2] f3 f1 [2] e7 ea [2] e8 f0 [2] f6 ed [2] f4 ec [2] ef ea [2] f3 ed [2] ef c2 }

  condition:
    any of them
}