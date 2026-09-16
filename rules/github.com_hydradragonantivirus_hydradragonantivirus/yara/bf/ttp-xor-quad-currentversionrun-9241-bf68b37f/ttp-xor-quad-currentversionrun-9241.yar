rule TTP_XOR_QUAD_CurrentVersionRun_9241 {
  strings:
    $key_9241 = { c1 2e [2] e5 20 [2] ce 0c [2] e0 2e [2] f4 35 [2] fb 2f [2] e5 32 [2] e7 33 [2] fc 35 [2] e0 32 [2] fc 1d }

  condition:
    any of them
}