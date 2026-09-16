rule TTP_XOR_QUAD_CurrentVersionRun_8c0a {
  strings:
    $key_8c0a = { df 65 [2] fb 6b [2] d0 47 [2] fe 65 [2] ea 7e [2] e5 64 [2] fb 79 [2] f9 78 [2] e2 7e [2] fe 79 [2] e2 56 }

  condition:
    any of them
}