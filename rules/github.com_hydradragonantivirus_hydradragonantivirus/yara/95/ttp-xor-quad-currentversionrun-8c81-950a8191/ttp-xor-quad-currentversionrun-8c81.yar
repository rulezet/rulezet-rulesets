rule TTP_XOR_QUAD_CurrentVersionRun_8c81 {
  strings:
    $key_8c81 = { df ee [2] fb e0 [2] d0 cc [2] fe ee [2] ea f5 [2] e5 ef [2] fb f2 [2] f9 f3 [2] e2 f5 [2] fe f2 [2] e2 dd }

  condition:
    any of them
}