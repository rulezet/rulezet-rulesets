rule TTP_XOR_QUAD_CurrentVersionRun_8c78 {
  strings:
    $key_8c78 = { df 17 [2] fb 19 [2] d0 35 [2] fe 17 [2] ea 0c [2] e5 16 [2] fb 0b [2] f9 0a [2] e2 0c [2] fe 0b [2] e2 24 }

  condition:
    any of them
}