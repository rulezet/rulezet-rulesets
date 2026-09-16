rule TTP_XOR_QUAD_CurrentVersionRun_8c2a {
  strings:
    $key_8c2a = { df 45 [2] fb 4b [2] d0 67 [2] fe 45 [2] ea 5e [2] e5 44 [2] fb 59 [2] f9 58 [2] e2 5e [2] fe 59 [2] e2 76 }

  condition:
    any of them
}