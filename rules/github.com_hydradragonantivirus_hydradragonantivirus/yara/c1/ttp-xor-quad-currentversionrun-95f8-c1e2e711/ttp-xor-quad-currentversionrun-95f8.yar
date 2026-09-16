rule TTP_XOR_QUAD_CurrentVersionRun_95f8 {
  strings:
    $key_95f8 = { c6 97 [2] e2 99 [2] c9 b5 [2] e7 97 [2] f3 8c [2] fc 96 [2] e2 8b [2] e0 8a [2] fb 8c [2] e7 8b [2] fb a4 }

  condition:
    any of them
}