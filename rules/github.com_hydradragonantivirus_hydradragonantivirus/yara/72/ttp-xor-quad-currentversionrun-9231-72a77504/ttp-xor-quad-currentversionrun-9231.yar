rule TTP_XOR_QUAD_CurrentVersionRun_9231 {
  strings:
    $key_9231 = { c1 5e [2] e5 50 [2] ce 7c [2] e0 5e [2] f4 45 [2] fb 5f [2] e5 42 [2] e7 43 [2] fc 45 [2] e0 42 [2] fc 6d }

  condition:
    any of them
}