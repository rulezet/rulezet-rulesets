rule TTP_XOR_QUAD_CurrentVersionRun_8c62 {
  strings:
    $key_8c62 = { df 0d [2] fb 03 [2] d0 2f [2] fe 0d [2] ea 16 [2] e5 0c [2] fb 11 [2] f9 10 [2] e2 16 [2] fe 11 [2] e2 3e }

  condition:
    any of them
}