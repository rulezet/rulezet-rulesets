rule TTP_XOR_QUAD_CurrentVersionRun_8c71 {
  strings:
    $key_8c71 = { df 1e [2] fb 10 [2] d0 3c [2] fe 1e [2] ea 05 [2] e5 1f [2] fb 02 [2] f9 03 [2] e2 05 [2] fe 02 [2] e2 2d }

  condition:
    any of them
}