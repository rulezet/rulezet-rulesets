rule TTP_XOR_QUAD_CurrentVersionRun_8ce4 {
  strings:
    $key_8ce4 = { df 8b [2] fb 85 [2] d0 a9 [2] fe 8b [2] ea 90 [2] e5 8a [2] fb 97 [2] f9 96 [2] e2 90 [2] fe 97 [2] e2 b8 }

  condition:
    any of them
}