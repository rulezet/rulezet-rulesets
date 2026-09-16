rule TTP_XOR_QUAD_CurrentVersionRun_955a {
  strings:
    $key_955a = { c6 35 [2] e2 3b [2] c9 17 [2] e7 35 [2] f3 2e [2] fc 34 [2] e2 29 [2] e0 28 [2] fb 2e [2] e7 29 [2] fb 06 }

  condition:
    any of them
}