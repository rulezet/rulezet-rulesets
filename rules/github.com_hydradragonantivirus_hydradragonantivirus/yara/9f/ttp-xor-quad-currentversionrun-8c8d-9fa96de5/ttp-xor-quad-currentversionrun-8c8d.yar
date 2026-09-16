rule TTP_XOR_QUAD_CurrentVersionRun_8c8d {
  strings:
    $key_8c8d = { df e2 [2] fb ec [2] d0 c0 [2] fe e2 [2] ea f9 [2] e5 e3 [2] fb fe [2] f9 ff [2] e2 f9 [2] fe fe [2] e2 d1 }

  condition:
    any of them
}