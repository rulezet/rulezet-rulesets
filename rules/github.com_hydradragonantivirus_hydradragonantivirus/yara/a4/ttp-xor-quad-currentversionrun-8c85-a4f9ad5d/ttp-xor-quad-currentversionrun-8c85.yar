rule TTP_XOR_QUAD_CurrentVersionRun_8c85 {
  strings:
    $key_8c85 = { df ea [2] fb e4 [2] d0 c8 [2] fe ea [2] ea f1 [2] e5 eb [2] fb f6 [2] f9 f7 [2] e2 f1 [2] fe f6 [2] e2 d9 }

  condition:
    any of them
}