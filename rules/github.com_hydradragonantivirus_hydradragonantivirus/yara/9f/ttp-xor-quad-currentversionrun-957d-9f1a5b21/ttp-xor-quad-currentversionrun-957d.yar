rule TTP_XOR_QUAD_CurrentVersionRun_957d {
  strings:
    $key_957d = { c6 12 [2] e2 1c [2] c9 30 [2] e7 12 [2] f3 09 [2] fc 13 [2] e2 0e [2] e0 0f [2] fb 09 [2] e7 0e [2] fb 21 }

  condition:
    any of them
}