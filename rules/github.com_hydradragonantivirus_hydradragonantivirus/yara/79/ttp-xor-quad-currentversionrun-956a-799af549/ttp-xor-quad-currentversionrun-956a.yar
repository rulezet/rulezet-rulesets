rule TTP_XOR_QUAD_CurrentVersionRun_956a {
  strings:
    $key_956a = { c6 05 [2] e2 0b [2] c9 27 [2] e7 05 [2] f3 1e [2] fc 04 [2] e2 19 [2] e0 18 [2] fb 1e [2] e7 19 [2] fb 36 }

  condition:
    any of them
}