rule TTP_XOR_QUAD_CurrentVersionRun_95e8 {
  strings:
    $key_95e8 = { c6 87 [2] e2 89 [2] c9 a5 [2] e7 87 [2] f3 9c [2] fc 86 [2] e2 9b [2] e0 9a [2] fb 9c [2] e7 9b [2] fb b4 }

  condition:
    any of them
}