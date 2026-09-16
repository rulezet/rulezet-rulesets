rule TTP_XOR_QUAD_CurrentVersionRun_951d {
  strings:
    $key_951d = { c6 72 [2] e2 7c [2] c9 50 [2] e7 72 [2] f3 69 [2] fc 73 [2] e2 6e [2] e0 6f [2] fb 69 [2] e7 6e [2] fb 41 }

  condition:
    any of them
}