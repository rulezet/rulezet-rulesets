rule TTP_XOR_QUAD_CurrentVersionRun_8e9e {
  strings:
    $key_8e9e = { dd f1 [2] f9 ff [2] d2 d3 [2] fc f1 [2] e8 ea [2] e7 f0 [2] f9 ed [2] fb ec [2] e0 ea [2] fc ed [2] e0 c2 }

  condition:
    any of them
}