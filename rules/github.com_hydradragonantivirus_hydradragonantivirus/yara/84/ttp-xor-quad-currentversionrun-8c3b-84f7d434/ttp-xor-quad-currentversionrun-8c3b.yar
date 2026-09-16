rule TTP_XOR_QUAD_CurrentVersionRun_8c3b {
  strings:
    $key_8c3b = { df 54 [2] fb 5a [2] d0 76 [2] fe 54 [2] ea 4f [2] e5 55 [2] fb 48 [2] f9 49 [2] e2 4f [2] fe 48 [2] e2 67 }

  condition:
    any of them
}