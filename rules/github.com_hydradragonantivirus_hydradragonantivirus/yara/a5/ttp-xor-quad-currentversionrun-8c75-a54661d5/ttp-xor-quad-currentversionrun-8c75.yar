rule TTP_XOR_QUAD_CurrentVersionRun_8c75 {
  strings:
    $key_8c75 = { df 1a [2] fb 14 [2] d0 38 [2] fe 1a [2] ea 01 [2] e5 1b [2] fb 06 [2] f9 07 [2] e2 01 [2] fe 06 [2] e2 29 }

  condition:
    any of them
}