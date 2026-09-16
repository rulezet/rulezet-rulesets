rule TTP_XOR_QUAD_CurrentVersionRun_9a48 {
  strings:
    $key_9a48 = { c9 27 [2] ed 29 [2] c6 05 [2] e8 27 [2] fc 3c [2] f3 26 [2] ed 3b [2] ef 3a [2] f4 3c [2] e8 3b [2] f4 14 }

  condition:
    any of them
}