rule TTP_XOR_QUAD_CurrentVersionRun_909e {
  strings:
    $key_909e = { c3 f1 [2] e7 ff [2] cc d3 [2] e2 f1 [2] f6 ea [2] f9 f0 [2] e7 ed [2] e5 ec [2] fe ea [2] e2 ed [2] fe c2 }

  condition:
    any of them
}