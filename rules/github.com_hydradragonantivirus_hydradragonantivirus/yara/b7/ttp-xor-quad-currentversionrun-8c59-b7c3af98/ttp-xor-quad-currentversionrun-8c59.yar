rule TTP_XOR_QUAD_CurrentVersionRun_8c59 {
  strings:
    $key_8c59 = { df 36 [2] fb 38 [2] d0 14 [2] fe 36 [2] ea 2d [2] e5 37 [2] fb 2a [2] f9 2b [2] e2 2d [2] fe 2a [2] e2 05 }

  condition:
    any of them
}