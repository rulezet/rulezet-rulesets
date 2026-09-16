rule TTP_XOR_QUAD_CurrentVersionRun_8cc7 {
  strings:
    $key_8cc7 = { df a8 [2] fb a6 [2] d0 8a [2] fe a8 [2] ea b3 [2] e5 a9 [2] fb b4 [2] f9 b5 [2] e2 b3 [2] fe b4 [2] e2 9b }

  condition:
    any of them
}