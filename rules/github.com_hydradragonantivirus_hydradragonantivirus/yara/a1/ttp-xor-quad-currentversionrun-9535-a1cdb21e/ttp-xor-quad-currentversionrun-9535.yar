rule TTP_XOR_QUAD_CurrentVersionRun_9535 {
  strings:
    $key_9535 = { c6 5a [2] e2 54 [2] c9 78 [2] e7 5a [2] f3 41 [2] fc 5b [2] e2 46 [2] e0 47 [2] fb 41 [2] e7 46 [2] fb 69 }

  condition:
    any of them
}