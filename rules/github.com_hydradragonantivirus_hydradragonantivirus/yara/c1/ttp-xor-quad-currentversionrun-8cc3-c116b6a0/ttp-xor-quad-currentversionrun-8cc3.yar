rule TTP_XOR_QUAD_CurrentVersionRun_8cc3 {
  strings:
    $key_8cc3 = { df ac [2] fb a2 [2] d0 8e [2] fe ac [2] ea b7 [2] e5 ad [2] fb b0 [2] f9 b1 [2] e2 b7 [2] fe b0 [2] e2 9f }

  condition:
    any of them
}