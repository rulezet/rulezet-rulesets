rule TTP_XOR_QUAD_CurrentVersionRun_8c4f {
  strings:
    $key_8c4f = { df 20 [2] fb 2e [2] d0 02 [2] fe 20 [2] ea 3b [2] e5 21 [2] fb 3c [2] f9 3d [2] e2 3b [2] fe 3c [2] e2 13 }

  condition:
    any of them
}