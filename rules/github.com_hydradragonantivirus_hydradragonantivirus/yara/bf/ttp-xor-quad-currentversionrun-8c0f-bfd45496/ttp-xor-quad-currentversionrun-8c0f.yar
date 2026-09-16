rule TTP_XOR_QUAD_CurrentVersionRun_8c0f {
  strings:
    $key_8c0f = { df 60 [2] fb 6e [2] d0 42 [2] fe 60 [2] ea 7b [2] e5 61 [2] fb 7c [2] f9 7d [2] e2 7b [2] fe 7c [2] e2 53 }

  condition:
    any of them
}