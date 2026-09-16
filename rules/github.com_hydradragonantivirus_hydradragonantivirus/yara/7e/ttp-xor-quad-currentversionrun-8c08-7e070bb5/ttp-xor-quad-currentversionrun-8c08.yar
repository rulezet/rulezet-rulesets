rule TTP_XOR_QUAD_CurrentVersionRun_8c08 {
  strings:
    $key_8c08 = { df 67 [2] fb 69 [2] d0 45 [2] fe 67 [2] ea 7c [2] e5 66 [2] fb 7b [2] f9 7a [2] e2 7c [2] fe 7b [2] e2 54 }

  condition:
    any of them
}