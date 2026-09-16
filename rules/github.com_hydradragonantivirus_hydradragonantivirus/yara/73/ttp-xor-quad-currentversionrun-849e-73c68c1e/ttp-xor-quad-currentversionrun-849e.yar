rule TTP_XOR_QUAD_CurrentVersionRun_849e {
  strings:
    $key_849e = { d7 f1 [2] f3 ff [2] d8 d3 [2] f6 f1 [2] e2 ea [2] ed f0 [2] f3 ed [2] f1 ec [2] ea ea [2] f6 ed [2] ea c2 }

  condition:
    any of them
}