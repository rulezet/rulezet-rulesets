rule TTP_XOR_QUAD_CurrentVersionRun_8c82 {
  strings:
    $key_8c82 = { df ed [2] fb e3 [2] d0 cf [2] fe ed [2] ea f6 [2] e5 ec [2] fb f1 [2] f9 f0 [2] e2 f6 [2] fe f1 [2] e2 de }

  condition:
    any of them
}