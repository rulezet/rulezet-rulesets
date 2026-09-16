rule TTP_XOR_QUAD_CurrentVersionRun_95d7 {
  strings:
    $key_95d7 = { c6 b8 [2] e2 b6 [2] c9 9a [2] e7 b8 [2] f3 a3 [2] fc b9 [2] e2 a4 [2] e0 a5 [2] fb a3 [2] e7 a4 [2] fb 8b }

  condition:
    any of them
}