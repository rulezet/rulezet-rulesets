rule TTP_XOR_QUAD_CurrentVersionRun_954d {
  strings:
    $key_954d = { c6 22 [2] e2 2c [2] c9 00 [2] e7 22 [2] f3 39 [2] fc 23 [2] e2 3e [2] e0 3f [2] fb 39 [2] e7 3e [2] fb 11 }

  condition:
    any of them
}