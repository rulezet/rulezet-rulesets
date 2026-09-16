rule TTP_XOR_QUAD_CurrentVersionRun_8ce2 {
  strings:
    $key_8ce2 = { df 8d [2] fb 83 [2] d0 af [2] fe 8d [2] ea 96 [2] e5 8c [2] fb 91 [2] f9 90 [2] e2 96 [2] fe 91 [2] e2 be }

  condition:
    any of them
}