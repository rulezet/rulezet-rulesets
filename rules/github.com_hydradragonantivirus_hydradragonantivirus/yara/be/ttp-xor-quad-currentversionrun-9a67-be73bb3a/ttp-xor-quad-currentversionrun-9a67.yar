rule TTP_XOR_QUAD_CurrentVersionRun_9a67 {
  strings:
    $key_9a67 = { c9 08 [2] ed 06 [2] c6 2a [2] e8 08 [2] fc 13 [2] f3 09 [2] ed 14 [2] ef 15 [2] f4 13 [2] e8 14 [2] f4 3b }

  condition:
    any of them
}