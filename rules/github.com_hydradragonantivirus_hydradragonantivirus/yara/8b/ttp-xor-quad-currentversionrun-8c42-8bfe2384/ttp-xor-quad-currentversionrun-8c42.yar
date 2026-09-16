rule TTP_XOR_QUAD_CurrentVersionRun_8c42 {
  strings:
    $key_8c42 = { df 2d [2] fb 23 [2] d0 0f [2] fe 2d [2] ea 36 [2] e5 2c [2] fb 31 [2] f9 30 [2] e2 36 [2] fe 31 [2] e2 1e }

  condition:
    any of them
}