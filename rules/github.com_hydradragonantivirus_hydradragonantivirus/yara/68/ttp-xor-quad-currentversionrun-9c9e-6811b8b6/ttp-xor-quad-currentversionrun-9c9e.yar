rule TTP_XOR_QUAD_CurrentVersionRun_9c9e {
  strings:
    $key_9c9e = { cf f1 [2] eb ff [2] c0 d3 [2] ee f1 [2] fa ea [2] f5 f0 [2] eb ed [2] e9 ec [2] f2 ea [2] ee ed [2] f2 c2 }

  condition:
    any of them
}