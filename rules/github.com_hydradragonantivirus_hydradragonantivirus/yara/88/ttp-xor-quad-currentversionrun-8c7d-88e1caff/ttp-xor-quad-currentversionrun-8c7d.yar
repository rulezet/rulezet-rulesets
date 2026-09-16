rule TTP_XOR_QUAD_CurrentVersionRun_8c7d {
  strings:
    $key_8c7d = { df 12 [2] fb 1c [2] d0 30 [2] fe 12 [2] ea 09 [2] e5 13 [2] fb 0e [2] f9 0f [2] e2 09 [2] fe 0e [2] e2 21 }

  condition:
    any of them
}