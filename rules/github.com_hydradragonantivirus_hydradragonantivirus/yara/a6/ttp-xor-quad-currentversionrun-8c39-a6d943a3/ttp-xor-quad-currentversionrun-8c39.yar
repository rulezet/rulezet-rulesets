rule TTP_XOR_QUAD_CurrentVersionRun_8c39 {
  strings:
    $key_8c39 = { df 56 [2] fb 58 [2] d0 74 [2] fe 56 [2] ea 4d [2] e5 57 [2] fb 4a [2] f9 4b [2] e2 4d [2] fe 4a [2] e2 65 }

  condition:
    any of them
}