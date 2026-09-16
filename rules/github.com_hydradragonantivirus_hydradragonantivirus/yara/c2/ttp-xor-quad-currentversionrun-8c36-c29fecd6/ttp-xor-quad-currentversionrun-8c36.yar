rule TTP_XOR_QUAD_CurrentVersionRun_8c36 {
  strings:
    $key_8c36 = { df 59 [2] fb 57 [2] d0 7b [2] fe 59 [2] ea 42 [2] e5 58 [2] fb 45 [2] f9 44 [2] e2 42 [2] fe 45 [2] e2 6a }

  condition:
    any of them
}