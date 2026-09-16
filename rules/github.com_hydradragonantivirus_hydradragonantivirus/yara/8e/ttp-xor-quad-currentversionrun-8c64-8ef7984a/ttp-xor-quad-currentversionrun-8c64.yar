rule TTP_XOR_QUAD_CurrentVersionRun_8c64 {
  strings:
    $key_8c64 = { df 0b [2] fb 05 [2] d0 29 [2] fe 0b [2] ea 10 [2] e5 0a [2] fb 17 [2] f9 16 [2] e2 10 [2] fe 17 [2] e2 38 }

  condition:
    any of them
}