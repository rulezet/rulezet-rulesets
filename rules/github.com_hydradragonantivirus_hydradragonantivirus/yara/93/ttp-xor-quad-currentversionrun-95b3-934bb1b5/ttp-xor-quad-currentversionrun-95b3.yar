rule TTP_XOR_QUAD_CurrentVersionRun_95b3 {
  strings:
    $key_95b3 = { c6 dc [2] e2 d2 [2] c9 fe [2] e7 dc [2] f3 c7 [2] fc dd [2] e2 c0 [2] e0 c1 [2] fb c7 [2] e7 c0 [2] fb ef }

  condition:
    any of them
}