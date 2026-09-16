rule TTP_XOR_QUAD_CurrentVersionRun_9a56 {
  strings:
    $key_9a56 = { c9 39 [2] ed 37 [2] c6 1b [2] e8 39 [2] fc 22 [2] f3 38 [2] ed 25 [2] ef 24 [2] f4 22 [2] e8 25 [2] f4 0a }

  condition:
    any of them
}