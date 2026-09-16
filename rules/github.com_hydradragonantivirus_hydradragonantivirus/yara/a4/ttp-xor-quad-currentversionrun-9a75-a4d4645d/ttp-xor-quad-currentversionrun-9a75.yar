rule TTP_XOR_QUAD_CurrentVersionRun_9a75 {
  strings:
    $key_9a75 = { c9 1a [2] ed 14 [2] c6 38 [2] e8 1a [2] fc 01 [2] f3 1b [2] ed 06 [2] ef 07 [2] f4 01 [2] e8 06 [2] f4 29 }

  condition:
    any of them
}