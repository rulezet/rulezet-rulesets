rule TTP_XOR_QUAD_CurrentVersionRun_8c51 {
  strings:
    $key_8c51 = { df 3e [2] fb 30 [2] d0 1c [2] fe 3e [2] ea 25 [2] e5 3f [2] fb 22 [2] f9 23 [2] e2 25 [2] fe 22 [2] e2 0d }

  condition:
    any of them
}