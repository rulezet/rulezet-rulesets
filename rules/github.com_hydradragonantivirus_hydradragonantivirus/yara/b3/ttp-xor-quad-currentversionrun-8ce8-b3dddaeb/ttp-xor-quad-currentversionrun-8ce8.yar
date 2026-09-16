rule TTP_XOR_QUAD_CurrentVersionRun_8ce8 {
  strings:
    $key_8ce8 = { df 87 [2] fb 89 [2] d0 a5 [2] fe 87 [2] ea 9c [2] e5 86 [2] fb 9b [2] f9 9a [2] e2 9c [2] fe 9b [2] e2 b4 }

  condition:
    any of them
}