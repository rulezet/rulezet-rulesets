rule TTP_XOR_QUAD_CurrentVersionRun_9206 {
  strings:
    $key_9206 = { c1 69 [2] e5 67 [2] ce 4b [2] e0 69 [2] f4 72 [2] fb 68 [2] e5 75 [2] e7 74 [2] fc 72 [2] e0 75 [2] fc 5a }

  condition:
    any of them
}