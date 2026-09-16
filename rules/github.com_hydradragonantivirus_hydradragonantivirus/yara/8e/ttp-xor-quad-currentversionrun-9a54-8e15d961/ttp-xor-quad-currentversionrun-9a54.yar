rule TTP_XOR_QUAD_CurrentVersionRun_9a54 {
  strings:
    $key_9a54 = { c9 3b [2] ed 35 [2] c6 19 [2] e8 3b [2] fc 20 [2] f3 3a [2] ed 27 [2] ef 26 [2] f4 20 [2] e8 27 [2] f4 08 }

  condition:
    any of them
}