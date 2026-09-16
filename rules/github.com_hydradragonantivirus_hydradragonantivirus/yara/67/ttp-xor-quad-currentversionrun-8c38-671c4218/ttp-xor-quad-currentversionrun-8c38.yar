rule TTP_XOR_QUAD_CurrentVersionRun_8c38 {
  strings:
    $key_8c38 = { df 57 [2] fb 59 [2] d0 75 [2] fe 57 [2] ea 4c [2] e5 56 [2] fb 4b [2] f9 4a [2] e2 4c [2] fe 4b [2] e2 64 }

  condition:
    any of them
}