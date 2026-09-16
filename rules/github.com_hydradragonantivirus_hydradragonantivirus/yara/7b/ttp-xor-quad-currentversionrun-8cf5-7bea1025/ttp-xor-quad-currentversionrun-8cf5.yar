rule TTP_XOR_QUAD_CurrentVersionRun_8cf5 {
  strings:
    $key_8cf5 = { df 9a [2] fb 94 [2] d0 b8 [2] fe 9a [2] ea 81 [2] e5 9b [2] fb 86 [2] f9 87 [2] e2 81 [2] fe 86 [2] e2 a9 }

  condition:
    any of them
}