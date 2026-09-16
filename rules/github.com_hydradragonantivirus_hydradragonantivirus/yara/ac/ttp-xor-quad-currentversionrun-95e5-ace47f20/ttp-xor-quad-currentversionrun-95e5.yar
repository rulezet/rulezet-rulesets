rule TTP_XOR_QUAD_CurrentVersionRun_95e5 {
  strings:
    $key_95e5 = { c6 8a [2] e2 84 [2] c9 a8 [2] e7 8a [2] f3 91 [2] fc 8b [2] e2 96 [2] e0 97 [2] fb 91 [2] e7 96 [2] fb b9 }

  condition:
    any of them
}