rule TTP_XOR_QUAD_CurrentVersionRun_8c83 {
  strings:
    $key_8c83 = { df ec [2] fb e2 [2] d0 ce [2] fe ec [2] ea f7 [2] e5 ed [2] fb f0 [2] f9 f1 [2] e2 f7 [2] fe f0 [2] e2 df }

  condition:
    any of them
}