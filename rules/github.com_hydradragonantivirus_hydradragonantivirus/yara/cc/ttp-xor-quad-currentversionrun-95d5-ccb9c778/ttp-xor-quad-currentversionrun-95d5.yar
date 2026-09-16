rule TTP_XOR_QUAD_CurrentVersionRun_95d5 {
  strings:
    $key_95d5 = { c6 ba [2] e2 b4 [2] c9 98 [2] e7 ba [2] f3 a1 [2] fc bb [2] e2 a6 [2] e0 a7 [2] fb a1 [2] e7 a6 [2] fb 89 }

  condition:
    any of them
}