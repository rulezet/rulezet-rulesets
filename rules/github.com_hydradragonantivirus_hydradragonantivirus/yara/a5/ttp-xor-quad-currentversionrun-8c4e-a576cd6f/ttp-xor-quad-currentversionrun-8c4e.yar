rule TTP_XOR_QUAD_CurrentVersionRun_8c4e {
  strings:
    $key_8c4e = { df 21 [2] fb 2f [2] d0 03 [2] fe 21 [2] ea 3a [2] e5 20 [2] fb 3d [2] f9 3c [2] e2 3a [2] fe 3d [2] e2 12 }

  condition:
    any of them
}