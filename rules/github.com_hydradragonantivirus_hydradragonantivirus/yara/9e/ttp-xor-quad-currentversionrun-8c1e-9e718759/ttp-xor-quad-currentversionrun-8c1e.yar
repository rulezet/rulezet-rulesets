rule TTP_XOR_QUAD_CurrentVersionRun_8c1e {
  strings:
    $key_8c1e = { df 71 [2] fb 7f [2] d0 53 [2] fe 71 [2] ea 6a [2] e5 70 [2] fb 6d [2] f9 6c [2] e2 6a [2] fe 6d [2] e2 42 }

  condition:
    any of them
}