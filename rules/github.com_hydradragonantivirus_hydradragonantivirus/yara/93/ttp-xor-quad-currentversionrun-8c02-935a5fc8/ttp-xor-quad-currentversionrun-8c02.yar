rule TTP_XOR_QUAD_CurrentVersionRun_8c02 {
  strings:
    $key_8c02 = { df 6d [2] fb 63 [2] d0 4f [2] fe 6d [2] ea 76 [2] e5 6c [2] fb 71 [2] f9 70 [2] e2 76 [2] fe 71 [2] e2 5e }

  condition:
    any of them
}