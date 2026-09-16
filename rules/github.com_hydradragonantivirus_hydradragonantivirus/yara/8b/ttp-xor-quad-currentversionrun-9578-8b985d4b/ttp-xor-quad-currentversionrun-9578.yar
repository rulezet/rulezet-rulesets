rule TTP_XOR_QUAD_CurrentVersionRun_9578 {
  strings:
    $key_9578 = { c6 17 [2] e2 19 [2] c9 35 [2] e7 17 [2] f3 0c [2] fc 16 [2] e2 0b [2] e0 0a [2] fb 0c [2] e7 0b [2] fb 24 }

  condition:
    any of them
}