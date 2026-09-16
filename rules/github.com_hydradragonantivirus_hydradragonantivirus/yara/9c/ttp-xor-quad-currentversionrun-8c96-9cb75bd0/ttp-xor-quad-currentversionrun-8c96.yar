rule TTP_XOR_QUAD_CurrentVersionRun_8c96 {
  strings:
    $key_8c96 = { df f9 [2] fb f7 [2] d0 db [2] fe f9 [2] ea e2 [2] e5 f8 [2] fb e5 [2] f9 e4 [2] e2 e2 [2] fe e5 [2] e2 ca }

  condition:
    any of them
}