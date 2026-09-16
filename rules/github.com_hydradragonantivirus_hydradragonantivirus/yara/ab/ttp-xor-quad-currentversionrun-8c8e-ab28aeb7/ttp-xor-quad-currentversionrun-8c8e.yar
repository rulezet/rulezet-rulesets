rule TTP_XOR_QUAD_CurrentVersionRun_8c8e {
  strings:
    $key_8c8e = { df e1 [2] fb ef [2] d0 c3 [2] fe e1 [2] ea fa [2] e5 e0 [2] fb fd [2] f9 fc [2] e2 fa [2] fe fd [2] e2 d2 }

  condition:
    any of them
}