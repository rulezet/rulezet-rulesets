rule TTP_XOR_QUAD_CurrentVersionRun_8c6e {
  strings:
    $key_8c6e = { df 01 [2] fb 0f [2] d0 23 [2] fe 01 [2] ea 1a [2] e5 00 [2] fb 1d [2] f9 1c [2] e2 1a [2] fe 1d [2] e2 32 }

  condition:
    any of them
}