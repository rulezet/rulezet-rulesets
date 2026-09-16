rule TTP_XOR_QUAD_CurrentVersionRun_8c57 {
  strings:
    $key_8c57 = { df 38 [2] fb 36 [2] d0 1a [2] fe 38 [2] ea 23 [2] e5 39 [2] fb 24 [2] f9 25 [2] e2 23 [2] fe 24 [2] e2 0b }

  condition:
    any of them
}