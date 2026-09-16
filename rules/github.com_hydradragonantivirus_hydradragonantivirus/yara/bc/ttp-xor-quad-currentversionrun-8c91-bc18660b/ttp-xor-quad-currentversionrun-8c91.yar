rule TTP_XOR_QUAD_CurrentVersionRun_8c91 {
  strings:
    $key_8c91 = { df fe [2] fb f0 [2] d0 dc [2] fe fe [2] ea e5 [2] e5 ff [2] fb e2 [2] f9 e3 [2] e2 e5 [2] fe e2 [2] e2 cd }

  condition:
    any of them
}