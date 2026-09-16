rule TTP_XOR_QUAD_CurrentVersionRun_95c6 {
  strings:
    $key_95c6 = { c6 a9 [2] e2 a7 [2] c9 8b [2] e7 a9 [2] f3 b2 [2] fc a8 [2] e2 b5 [2] e0 b4 [2] fb b2 [2] e7 b5 [2] fb 9a }

  condition:
    any of them
}