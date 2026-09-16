rule TTP_XOR_QUAD_CurrentVersionRun_8c4b {
  strings:
    $key_8c4b = { df 24 [2] fb 2a [2] d0 06 [2] fe 24 [2] ea 3f [2] e5 25 [2] fb 38 [2] f9 39 [2] e2 3f [2] fe 38 [2] e2 17 }

  condition:
    any of them
}