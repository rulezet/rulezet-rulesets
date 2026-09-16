rule TTP_XOR_QUAD_CurrentVersionRun_9501 {
  strings:
    $key_9501 = { c6 6e [2] e2 60 [2] c9 4c [2] e7 6e [2] f3 75 [2] fc 6f [2] e2 72 [2] e0 73 [2] fb 75 [2] e7 72 [2] fb 5d }

  condition:
    any of them
}