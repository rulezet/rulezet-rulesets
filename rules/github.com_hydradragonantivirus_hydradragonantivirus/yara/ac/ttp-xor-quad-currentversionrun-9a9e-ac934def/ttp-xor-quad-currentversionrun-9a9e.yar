rule TTP_XOR_QUAD_CurrentVersionRun_9a9e {
  strings:
    $key_9a9e = { c9 f1 [2] ed ff [2] c6 d3 [2] e8 f1 [2] fc ea [2] f3 f0 [2] ed ed [2] ef ec [2] f4 ea [2] e8 ed [2] f4 c2 }

  condition:
    any of them
}