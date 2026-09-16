rule TTP_XOR_QUAD_CurrentVersionRun_8c7a {
  strings:
    $key_8c7a = { df 15 [2] fb 1b [2] d0 37 [2] fe 15 [2] ea 0e [2] e5 14 [2] fb 09 [2] f9 08 [2] e2 0e [2] fe 09 [2] e2 26 }

  condition:
    any of them
}