rule TTP_XOR_QUAD_CurrentVersionRun_8c1d {
  strings:
    $key_8c1d = { df 72 [2] fb 7c [2] d0 50 [2] fe 72 [2] ea 69 [2] e5 73 [2] fb 6e [2] f9 6f [2] e2 69 [2] fe 6e [2] e2 41 }

  condition:
    any of them
}