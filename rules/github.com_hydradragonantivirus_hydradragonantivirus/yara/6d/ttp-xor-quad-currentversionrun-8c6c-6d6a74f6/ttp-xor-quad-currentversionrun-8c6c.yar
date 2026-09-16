rule TTP_XOR_QUAD_CurrentVersionRun_8c6c {
  strings:
    $key_8c6c = { df 03 [2] fb 0d [2] d0 21 [2] fe 03 [2] ea 18 [2] e5 02 [2] fb 1f [2] f9 1e [2] e2 18 [2] fe 1f [2] e2 30 }

  condition:
    any of them
}