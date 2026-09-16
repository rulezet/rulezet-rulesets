rule TTP_XOR_QUAD_CurrentVersionRun_8c37 {
  strings:
    $key_8c37 = { df 58 [2] fb 56 [2] d0 7a [2] fe 58 [2] ea 43 [2] e5 59 [2] fb 44 [2] f9 45 [2] e2 43 [2] fe 44 [2] e2 6b }

  condition:
    any of them
}