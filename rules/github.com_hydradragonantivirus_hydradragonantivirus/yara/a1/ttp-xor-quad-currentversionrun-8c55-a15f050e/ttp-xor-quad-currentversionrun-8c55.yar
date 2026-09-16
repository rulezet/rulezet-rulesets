rule TTP_XOR_QUAD_CurrentVersionRun_8c55 {
  strings:
    $key_8c55 = { df 3a [2] fb 34 [2] d0 18 [2] fe 3a [2] ea 21 [2] e5 3b [2] fb 26 [2] f9 27 [2] e2 21 [2] fe 26 [2] e2 09 }

  condition:
    any of them
}