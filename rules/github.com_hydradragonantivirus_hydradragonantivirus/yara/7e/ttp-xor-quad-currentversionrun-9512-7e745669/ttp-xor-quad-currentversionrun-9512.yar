rule TTP_XOR_QUAD_CurrentVersionRun_9512 {
  strings:
    $key_9512 = { c6 7d [2] e2 73 [2] c9 5f [2] e7 7d [2] f3 66 [2] fc 7c [2] e2 61 [2] e0 60 [2] fb 66 [2] e7 61 [2] fb 4e }

  condition:
    any of them
}