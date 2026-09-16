rule TTP_XOR_QUAD_CurrentVersionRun_9531 {
  strings:
    $key_9531 = { c6 5e [2] e2 50 [2] c9 7c [2] e7 5e [2] f3 45 [2] fc 5f [2] e2 42 [2] e0 43 [2] fb 45 [2] e7 42 [2] fb 6d }

  condition:
    any of them
}