rule TTP_XOR_QUAD_CurrentVersionRun_9a39 {
  strings:
    $key_9a39 = { c9 56 [2] ed 58 [2] c6 74 [2] e8 56 [2] fc 4d [2] f3 57 [2] ed 4a [2] ef 4b [2] f4 4d [2] e8 4a [2] f4 65 }

  condition:
    any of them
}