rule TTP_XOR_QUAD_CurrentVersionRun_8c13 {
  strings:
    $key_8c13 = { df 7c [2] fb 72 [2] d0 5e [2] fe 7c [2] ea 67 [2] e5 7d [2] fb 60 [2] f9 61 [2] e2 67 [2] fe 60 [2] e2 4f }

  condition:
    any of them
}