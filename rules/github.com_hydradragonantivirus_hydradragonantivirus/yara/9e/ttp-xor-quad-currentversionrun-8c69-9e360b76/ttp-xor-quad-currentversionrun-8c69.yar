rule TTP_XOR_QUAD_CurrentVersionRun_8c69 {
  strings:
    $key_8c69 = { df 06 [2] fb 08 [2] d0 24 [2] fe 06 [2] ea 1d [2] e5 07 [2] fb 1a [2] f9 1b [2] e2 1d [2] fe 1a [2] e2 35 }

  condition:
    any of them
}