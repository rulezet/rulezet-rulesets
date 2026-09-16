rule TTP_XOR_QUAD_CurrentVersionRun_8cc6 {
  strings:
    $key_8cc6 = { df a9 [2] fb a7 [2] d0 8b [2] fe a9 [2] ea b2 [2] e5 a8 [2] fb b5 [2] f9 b4 [2] e2 b2 [2] fe b5 [2] e2 9a }

  condition:
    any of them
}