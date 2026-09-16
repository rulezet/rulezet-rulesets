rule TTP_XOR_QUAD_CurrentVersionRun_9f9e {
  strings:
    $key_9f9e = { cc f1 [2] e8 ff [2] c3 d3 [2] ed f1 [2] f9 ea [2] f6 f0 [2] e8 ed [2] ea ec [2] f1 ea [2] ed ed [2] f1 c2 }

  condition:
    any of them
}