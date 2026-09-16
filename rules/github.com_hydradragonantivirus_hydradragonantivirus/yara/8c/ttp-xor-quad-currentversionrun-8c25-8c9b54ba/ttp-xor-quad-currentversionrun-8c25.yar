rule TTP_XOR_QUAD_CurrentVersionRun_8c25 {
  strings:
    $key_8c25 = { df 4a [2] fb 44 [2] d0 68 [2] fe 4a [2] ea 51 [2] e5 4b [2] fb 56 [2] f9 57 [2] e2 51 [2] fe 56 [2] e2 79 }

  condition:
    any of them
}