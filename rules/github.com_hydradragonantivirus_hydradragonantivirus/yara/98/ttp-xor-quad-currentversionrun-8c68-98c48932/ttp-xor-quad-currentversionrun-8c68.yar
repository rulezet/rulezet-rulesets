rule TTP_XOR_QUAD_CurrentVersionRun_8c68 {
  strings:
    $key_8c68 = { df 07 [2] fb 09 [2] d0 25 [2] fe 07 [2] ea 1c [2] e5 06 [2] fb 1b [2] f9 1a [2] e2 1c [2] fe 1b [2] e2 34 }

  condition:
    any of them
}