rule TTP_XOR_QUAD_CurrentVersionRun_9a08 {
  strings:
    $key_9a08 = { c9 67 [2] ed 69 [2] c6 45 [2] e8 67 [2] fc 7c [2] f3 66 [2] ed 7b [2] ef 7a [2] f4 7c [2] e8 7b [2] f4 54 }

  condition:
    any of them
}