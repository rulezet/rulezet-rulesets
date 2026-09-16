rule TTP_XOR_QUAD_CurrentVersionRun_8c17 {
  strings:
    $key_8c17 = { df 78 [2] fb 76 [2] d0 5a [2] fe 78 [2] ea 63 [2] e5 79 [2] fb 64 [2] f9 65 [2] e2 63 [2] fe 64 [2] e2 4b }

  condition:
    any of them
}