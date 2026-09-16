rule TTP_XOR_QUAD_CurrentVersionRun_9d9e {
  strings:
    $key_9d9e = { ce f1 [2] ea ff [2] c1 d3 [2] ef f1 [2] fb ea [2] f4 f0 [2] ea ed [2] e8 ec [2] f3 ea [2] ef ed [2] f3 c2 }

  condition:
    any of them
}