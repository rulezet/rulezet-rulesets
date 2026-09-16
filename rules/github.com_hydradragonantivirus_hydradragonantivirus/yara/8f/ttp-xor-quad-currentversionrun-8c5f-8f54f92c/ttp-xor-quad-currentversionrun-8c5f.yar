rule TTP_XOR_QUAD_CurrentVersionRun_8c5f {
  strings:
    $key_8c5f = { df 30 [2] fb 3e [2] d0 12 [2] fe 30 [2] ea 2b [2] e5 31 [2] fb 2c [2] f9 2d [2] e2 2b [2] fe 2c [2] e2 03 }

  condition:
    any of them
}