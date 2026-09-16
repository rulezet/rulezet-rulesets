rule TTP_XOR_QUAD_CurrentVersionRun_95e4 {
  strings:
    $key_95e4 = { c6 8b [2] e2 85 [2] c9 a9 [2] e7 8b [2] f3 90 [2] fc 8a [2] e2 97 [2] e0 96 [2] fb 90 [2] e7 97 [2] fb b8 }

  condition:
    any of them
}