rule TTP_XOR_QUAD_CurrentVersionRun_9532 {
  strings:
    $key_9532 = { c6 5d [2] e2 53 [2] c9 7f [2] e7 5d [2] f3 46 [2] fc 5c [2] e2 41 [2] e0 40 [2] fb 46 [2] e7 41 [2] fb 6e }

  condition:
    any of them
}