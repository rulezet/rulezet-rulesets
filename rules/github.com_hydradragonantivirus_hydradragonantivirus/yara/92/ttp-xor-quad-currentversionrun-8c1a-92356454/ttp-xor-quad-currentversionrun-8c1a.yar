rule TTP_XOR_QUAD_CurrentVersionRun_8c1a {
  strings:
    $key_8c1a = { df 75 [2] fb 7b [2] d0 57 [2] fe 75 [2] ea 6e [2] e5 74 [2] fb 69 [2] f9 68 [2] e2 6e [2] fe 69 [2] e2 46 }

  condition:
    any of them
}