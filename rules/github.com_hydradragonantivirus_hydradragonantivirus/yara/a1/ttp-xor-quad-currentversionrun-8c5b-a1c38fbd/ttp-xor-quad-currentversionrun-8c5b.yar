rule TTP_XOR_QUAD_CurrentVersionRun_8c5b {
  strings:
    $key_8c5b = { df 34 [2] fb 3a [2] d0 16 [2] fe 34 [2] ea 2f [2] e5 35 [2] fb 28 [2] f9 29 [2] e2 2f [2] fe 28 [2] e2 07 }

  condition:
    any of them
}