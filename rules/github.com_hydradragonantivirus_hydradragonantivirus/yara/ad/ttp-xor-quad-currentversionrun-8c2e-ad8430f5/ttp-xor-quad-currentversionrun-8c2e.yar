rule TTP_XOR_QUAD_CurrentVersionRun_8c2e {
  strings:
    $key_8c2e = { df 41 [2] fb 4f [2] d0 63 [2] fe 41 [2] ea 5a [2] e5 40 [2] fb 5d [2] f9 5c [2] e2 5a [2] fe 5d [2] e2 72 }

  condition:
    any of them
}