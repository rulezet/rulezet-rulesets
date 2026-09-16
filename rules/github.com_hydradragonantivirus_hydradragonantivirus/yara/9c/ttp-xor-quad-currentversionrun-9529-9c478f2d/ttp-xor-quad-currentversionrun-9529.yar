rule TTP_XOR_QUAD_CurrentVersionRun_9529 {
  strings:
    $key_9529 = { c6 46 [2] e2 48 [2] c9 64 [2] e7 46 [2] f3 5d [2] fc 47 [2] e2 5a [2] e0 5b [2] fb 5d [2] e7 5a [2] fb 75 }

  condition:
    any of them
}