rule TTP_XOR_QUAD_CurrentVersionRun_95f9 {
  strings:
    $key_95f9 = { c6 96 [2] e2 98 [2] c9 b4 [2] e7 96 [2] f3 8d [2] fc 97 [2] e2 8a [2] e0 8b [2] fb 8d [2] e7 8a [2] fb a5 }

  condition:
    any of them
}