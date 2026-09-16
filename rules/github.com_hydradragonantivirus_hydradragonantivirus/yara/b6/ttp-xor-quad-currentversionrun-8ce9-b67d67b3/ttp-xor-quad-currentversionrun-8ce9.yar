rule TTP_XOR_QUAD_CurrentVersionRun_8ce9 {
  strings:
    $key_8ce9 = { df 86 [2] fb 88 [2] d0 a4 [2] fe 86 [2] ea 9d [2] e5 87 [2] fb 9a [2] f9 9b [2] e2 9d [2] fe 9a [2] e2 b5 }

  condition:
    any of them
}