rule TTP_XOR_QUAD_CurrentVersionRun_8c49 {
  strings:
    $key_8c49 = { df 26 [2] fb 28 [2] d0 04 [2] fe 26 [2] ea 3d [2] e5 27 [2] fb 3a [2] f9 3b [2] e2 3d [2] fe 3a [2] e2 15 }

  condition:
    any of them
}