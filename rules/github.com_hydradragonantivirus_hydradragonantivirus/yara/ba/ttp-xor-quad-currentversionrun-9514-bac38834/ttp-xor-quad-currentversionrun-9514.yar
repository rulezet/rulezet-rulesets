rule TTP_XOR_QUAD_CurrentVersionRun_9514 {
  strings:
    $key_9514 = { c6 7b [2] e2 75 [2] c9 59 [2] e7 7b [2] f3 60 [2] fc 7a [2] e2 67 [2] e0 66 [2] fb 60 [2] e7 67 [2] fb 48 }

  condition:
    any of them
}