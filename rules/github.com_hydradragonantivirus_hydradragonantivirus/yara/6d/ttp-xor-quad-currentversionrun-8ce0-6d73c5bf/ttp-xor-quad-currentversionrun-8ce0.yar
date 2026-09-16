rule TTP_XOR_QUAD_CurrentVersionRun_8ce0 {
  strings:
    $key_8ce0 = { df 8f [2] fb 81 [2] d0 ad [2] fe 8f [2] ea 94 [2] e5 8e [2] fb 93 [2] f9 92 [2] e2 94 [2] fe 93 [2] e2 bc }

  condition:
    any of them
}