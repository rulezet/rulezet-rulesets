rule TTP_XOR_QUAD_CurrentVersionRun_8c3f {
  strings:
    $key_8c3f = { df 50 [2] fb 5e [2] d0 72 [2] fe 50 [2] ea 4b [2] e5 51 [2] fb 4c [2] f9 4d [2] e2 4b [2] fe 4c [2] e2 63 }

  condition:
    any of them
}