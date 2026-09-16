rule TTP_XOR_QUAD_CurrentVersionRun_989e {
  strings:
    $key_989e = { cb f1 [2] ef ff [2] c4 d3 [2] ea f1 [2] fe ea [2] f1 f0 [2] ef ed [2] ed ec [2] f6 ea [2] ea ed [2] f6 c2 }

  condition:
    any of them
}